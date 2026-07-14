//! Lifts decoded RV64IM instructions to the architecture-neutral IR and
//! builds basic blocks.

use crate::{Insn, Mnemonic};
use gu_ir::{BinOp, Block, CmpOp, Expr, LiftedFn, Stmt, UnOp, Value};
use std::collections::{BTreeMap, BTreeSet};

const REG_RA: u8 = 1;

pub struct Lifter {
    next_tmp: u32,
}

impl Default for Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifter {
    pub fn new() -> Self {
        Lifter { next_tmp: 0 }
    }

    fn tmp(&mut self) -> Value {
        let t = Value::Tmp(self.next_tmp);
        self.next_tmp += 1;
        t
    }

    /// Reads of x0 are the constant 0.
    fn src(reg: u8) -> Value {
        if reg == 0 {
            Value::Imm(0)
        } else {
            Value::Reg(reg as u16)
        }
    }

    /// Writes to x0 are discarded (x0 is hardwired to zero).
    fn assign(out: &mut Vec<Stmt>, rd: u8, expr: Expr) {
        if rd != 0 {
            out.push(Stmt::Assign { dst: Value::Reg(rd as u16), expr });
        }
    }

    /// rs1 + imm as a Value, materializing a temporary only when needed.
    fn addr_of(&mut self, out: &mut Vec<Stmt>, rs1: u8, imm: i64) -> Value {
        if imm == 0 {
            Self::src(rs1)
        } else {
            let t = self.tmp();
            out.push(Stmt::Assign {
                dst: t,
                expr: Expr::Bin(BinOp::Add, Self::src(rs1), Value::Imm(imm)),
            });
            t
        }
    }

    fn bin(out: &mut Vec<Stmt>, rd: u8, op: BinOp, a: Value, b: Value) {
        Self::assign(out, rd, Expr::Bin(op, a, b));
    }

    /// 32-bit op: compute in 64 bits, then sign-extend the low word.
    fn bin32(&mut self, out: &mut Vec<Stmt>, rd: u8, op: BinOp, a: Value, b: Value) {
        if rd == 0 {
            return;
        }
        let t = self.tmp();
        out.push(Stmt::Assign { dst: t, expr: Expr::Bin(op, a, b) });
        Self::assign(out, rd, Expr::Un(UnOp::Sext32, t));
    }

    /// Appends the IR for one instruction to `out`.
    pub fn lift(&mut self, insn: &Insn, out: &mut Vec<Stmt>) {
        use Mnemonic::*;
        let rd = insn.rd;
        let rs1 = Self::src(insn.rs1);
        let rs2 = Self::src(insn.rs2);
        let imm = Value::Imm(insn.imm);
        let target = insn.addr.wrapping_add(insn.imm as u64);

        match insn.mn {
            Lui => Self::assign(out, rd, Expr::Val(imm)),
            Auipc => Self::assign(out, rd, Expr::Val(Value::Imm(target as i64))),

            Jal => {
                if rd == REG_RA {
                    out.push(Stmt::Call { target });
                } else {
                    Self::assign(out, rd, Expr::Val(Value::Imm(insn.addr as i64 + 4)));
                    out.push(Stmt::Jump { target });
                }
            }
            Jalr => {
                let dest = self.addr_of(out, insn.rs1, insn.imm);
                if rd == REG_RA {
                    out.push(Stmt::CallIndirect { addr: dest });
                } else if rd == 0 && insn.rs1 == REG_RA && insn.imm == 0 {
                    out.push(Stmt::Return);
                } else {
                    Self::assign(out, rd, Expr::Val(Value::Imm(insn.addr as i64 + 4)));
                    out.push(Stmt::JumpIndirect { addr: dest });
                }
            }

            Beq => out.push(Stmt::CondJump { op: CmpOp::Eq, lhs: rs1, rhs: rs2, target }),
            Bne => out.push(Stmt::CondJump { op: CmpOp::Ne, lhs: rs1, rhs: rs2, target }),
            Blt => out.push(Stmt::CondJump { op: CmpOp::LtS, lhs: rs1, rhs: rs2, target }),
            Bge => out.push(Stmt::CondJump { op: CmpOp::GeS, lhs: rs1, rhs: rs2, target }),
            Bltu => out.push(Stmt::CondJump { op: CmpOp::LtU, lhs: rs1, rhs: rs2, target }),
            Bgeu => out.push(Stmt::CondJump { op: CmpOp::GeU, lhs: rs1, rhs: rs2, target }),

            Lb | Lh | Lw | Ld | Lbu | Lhu | Lwu => {
                let (size, signed) = match insn.mn {
                    Lb => (1, true),
                    Lbu => (1, false),
                    Lh => (2, true),
                    Lhu => (2, false),
                    Lw => (4, true),
                    Lwu => (4, false),
                    _ => (8, true),
                };
                let addr = self.addr_of(out, insn.rs1, insn.imm);
                Self::assign(out, rd, Expr::Load { addr, size, signed });
            }
            Sb | Sh | Sw | Sd => {
                let size = match insn.mn {
                    Sb => 1,
                    Sh => 2,
                    Sw => 4,
                    _ => 8,
                };
                let addr = self.addr_of(out, insn.rs1, insn.imm);
                out.push(Stmt::Store { addr, val: rs2, size });
            }

            Addi => Self::bin(out, rd, BinOp::Add, rs1, imm),
            Slti => Self::bin(out, rd, BinOp::SltS, rs1, imm),
            Sltiu => Self::bin(out, rd, BinOp::SltU, rs1, imm),
            Xori => Self::bin(out, rd, BinOp::Xor, rs1, imm),
            Ori => Self::bin(out, rd, BinOp::Or, rs1, imm),
            Andi => Self::bin(out, rd, BinOp::And, rs1, imm),
            Slli => Self::bin(out, rd, BinOp::Shl, rs1, imm),
            Srli => Self::bin(out, rd, BinOp::Shr, rs1, imm),
            Srai => Self::bin(out, rd, BinOp::Sar, rs1, imm),

            Addiw => self.bin32(out, rd, BinOp::Add, rs1, imm),
            Slliw => self.bin32(out, rd, BinOp::Shl, rs1, imm),
            Srliw => self.bin32(out, rd, BinOp::Shr, rs1, imm),
            Sraiw => self.bin32(out, rd, BinOp::Sar, rs1, imm),

            Add => Self::bin(out, rd, BinOp::Add, rs1, rs2),
            Sub => Self::bin(out, rd, BinOp::Sub, rs1, rs2),
            Sll => Self::bin(out, rd, BinOp::Shl, rs1, rs2),
            Slt => Self::bin(out, rd, BinOp::SltS, rs1, rs2),
            Sltu => Self::bin(out, rd, BinOp::SltU, rs1, rs2),
            Xor => Self::bin(out, rd, BinOp::Xor, rs1, rs2),
            Srl => Self::bin(out, rd, BinOp::Shr, rs1, rs2),
            Sra => Self::bin(out, rd, BinOp::Sar, rs1, rs2),
            Or => Self::bin(out, rd, BinOp::Or, rs1, rs2),
            And => Self::bin(out, rd, BinOp::And, rs1, rs2),

            Addw => self.bin32(out, rd, BinOp::Add, rs1, rs2),
            Subw => self.bin32(out, rd, BinOp::Sub, rs1, rs2),
            Sllw => self.bin32(out, rd, BinOp::Shl, rs1, rs2),
            Srlw => self.bin32(out, rd, BinOp::Shr, rs1, rs2),
            Sraw => self.bin32(out, rd, BinOp::Sar, rs1, rs2),

            Mul => Self::bin(out, rd, BinOp::Mul, rs1, rs2),
            Mulh => Self::bin(out, rd, BinOp::MulHS, rs1, rs2),
            Mulhsu => Self::bin(out, rd, BinOp::MulHSU, rs1, rs2),
            Mulhu => Self::bin(out, rd, BinOp::MulHU, rs1, rs2),
            Div => Self::bin(out, rd, BinOp::DivS, rs1, rs2),
            Divu => Self::bin(out, rd, BinOp::DivU, rs1, rs2),
            Rem => Self::bin(out, rd, BinOp::RemS, rs1, rs2),
            Remu => Self::bin(out, rd, BinOp::RemU, rs1, rs2),

            Mulw => self.bin32(out, rd, BinOp::Mul, rs1, rs2),
            Divw => self.bin32(out, rd, BinOp::DivS, rs1, rs2),
            Divuw => self.bin32(out, rd, BinOp::DivU, rs1, rs2),
            Remw => self.bin32(out, rd, BinOp::RemS, rs1, rs2),
            Remuw => self.bin32(out, rd, BinOp::RemU, rs1, rs2),

            Ecall => out.push(Stmt::SysCall),
            Ebreak => out.push(Stmt::Break),
            Fence | Unknown => out.push(Stmt::Nop),
        }
    }
}

/// Builds a CFG over the instructions of one function and lifts each basic
/// block. `insns` must be the function's instructions in address order.
pub fn lift_function(name: &str, insns: &[Insn]) -> LiftedFn {
    lift_function_with_tables(name, insns, &BTreeMap::new())
}

/// Lifts a function, treating each indirect jump listed in `jump_tables`
/// (address -> resolved target addresses) as a multi-way branch to those
/// targets. This is what connects a resolved switch to its case blocks so
/// they survive into the CFG and SSA.
pub fn lift_function_with_tables(
    name: &str,
    insns: &[Insn],
    jump_tables: &BTreeMap<u64, Vec<u64>>,
) -> LiftedFn {
    let Some(first) = insns.first() else {
        return LiftedFn { name: name.to_string(), entry: 0, blocks: Vec::new() };
    };
    let entry = first.addr;
    let end = insns.last().map(|i| i.addr + 4).unwrap_or(entry);
    let in_range = |a: u64| a >= entry && a < end;

    // Block leaders: the entry, every in-range branch target, every
    // instruction following a block terminator, and every resolved jump
    // table case target.
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(entry);
    for insn in insns {
        if let Some(t) = insn.branch_target() {
            if in_range(t) {
                leaders.insert(t);
            }
        }
        if insn.is_block_end() && in_range(insn.addr + 4) {
            leaders.insert(insn.addr + 4);
        }
        if let Some(targets) = jump_tables.get(&insn.addr) {
            leaders.extend(targets.iter().copied().filter(|&t| in_range(t)));
        }
    }

    let mut lifter = Lifter::new();
    let mut blocks = Vec::new();
    let leader_list: Vec<u64> = leaders.iter().copied().collect();

    for (bi, &start) in leader_list.iter().enumerate() {
        let block_end = leader_list.get(bi + 1).copied().unwrap_or(end);
        let body: Vec<&Insn> =
            insns.iter().filter(|i| i.addr >= start && i.addr < block_end).collect();

        let mut stmts = Vec::new();
        for insn in &body {
            let mut s = Vec::new();
            lifter.lift(insn, &mut s);
            stmts.extend(s.into_iter().map(|st| (insn.addr, st)));
        }

        let succs = match body.last() {
            Some(last) if last.is_block_end() => {
                use Mnemonic::*;
                match last.mn {
                    Beq | Bne | Blt | Bge | Bltu | Bgeu => {
                        let mut s = Vec::new();
                        if let Some(t) = last.branch_target().filter(|&t| in_range(t)) {
                            s.push(t);
                        }
                        if in_range(last.addr + 4) {
                            s.push(last.addr + 4);
                        }
                        s
                    }
                    Jal => last.branch_target().filter(|&t| in_range(t)).into_iter().collect(),
                    // A resolved indirect jump branches to its table targets.
                    Jalr if jump_tables.contains_key(&last.addr) => jump_tables[&last.addr]
                        .iter()
                        .copied()
                        .filter(|&t| in_range(t))
                        .collect(),
                    _ => Vec::new(), // returns and unresolved indirect jumps
                }
            }
            Some(_) if in_range(block_end) => vec![block_end],
            _ => Vec::new(),
        };

        blocks.push(Block { start, stmts, succs });
    }

    LiftedFn { name: name.to_string(), entry, blocks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_all;
    use crate::Rv64Namer;

    /// The sum_to_n function from fixtures/sum.s, encodings via llvm-mc.
    const SUM_TO_N: [u32; 8] = [
        0x00000293, // addi t0, zero, 0
        0x00100313, // addi t1, zero, 1
        0x00654863, // blt a0, t1, +16
        0x006282b3, // add t0, t0, t1
        0x00130313, // addi t1, t1, 1
        0xff5ff06f, // jal zero, -12
        0x00028513, // addi a0, t0, 0
        0x00008067, // jalr zero, 0(ra)
    ];

    fn fixture_insns() -> Vec<Insn> {
        let bytes: Vec<u8> = SUM_TO_N.iter().flat_map(|w| w.to_le_bytes()).collect();
        decode_all(0, &bytes)
    }

    #[test]
    fn builds_loop_cfg() {
        let f = lift_function("sum_to_n", &fixture_insns());
        // Blocks: entry [0,8), loop head [8,c), loop body [c,18), exit [18,20).
        let starts: Vec<u64> = f.blocks.iter().map(|b| b.start).collect();
        assert_eq!(starts, [0x0, 0x8, 0xc, 0x18]);
        assert_eq!(f.blocks[0].succs, [0x8]);
        assert_eq!(f.blocks[1].succs, [0x18, 0xc]); // taken, fallthrough
        assert_eq!(f.blocks[2].succs, [0x8]); // back edge
        assert!(f.blocks[3].succs.is_empty()); // return
    }

    #[test]
    fn lifts_x0_semantics() {
        // addi t0, zero, 0 must read the constant 0, not register x0.
        let f = lift_function("sum_to_n", &fixture_insns());
        let (_, first) = &f.blocks[0].stmts[0];
        assert_eq!(
            *first,
            Stmt::Assign {
                dst: Value::Reg(5),
                expr: Expr::Bin(BinOp::Add, Value::Imm(0), Value::Imm(0))
            }
        );
        // jalr zero, 0(ra) must lift to a return.
        let (_, last) = f.blocks[3].stmts.last().unwrap();
        assert_eq!(*last, Stmt::Return);
    }

    #[test]
    fn renders_readably() {
        let f = lift_function("sum_to_n", &fixture_insns());
        let text = f.render(&Rv64Namer);
        assert!(text.contains("if (a0 <s t1) goto 0x18"), "got:\n{text}");
        assert!(text.contains("t0 = t0 + t1"), "got:\n{text}");
        assert!(text.contains("return"), "got:\n{text}");
    }
}
