//! RV64IM instruction decoder and lifter.
//!
//! In the full design this hand-written decoder is a placeholder for
//! lifters generated from declarative processor specifications (the Sleigh
//! idea). It exists so the rest of the pipeline has real instructions to
//! work with, and is differentially tested against encodings produced by
//! llvm-mc (see tests).

#![forbid(unsafe_code)]

mod lift;

pub use lift::{lift_function, Lifter};

pub const REG_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

pub struct Rv64Namer;

impl gu_ir::RegNamer for Rv64Namer {
    fn reg_name(&self, reg: u16) -> &'static str {
        REG_NAMES.get(reg as usize).copied().unwrap_or("?")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mnemonic {
    Lui, Auipc,
    Jal, Jalr,
    Beq, Bne, Blt, Bge, Bltu, Bgeu,
    Lb, Lh, Lw, Ld, Lbu, Lhu, Lwu,
    Sb, Sh, Sw, Sd,
    Addi, Slti, Sltiu, Xori, Ori, Andi, Slli, Srli, Srai,
    Addiw, Slliw, Srliw, Sraiw,
    Add, Sub, Sll, Slt, Sltu, Xor, Srl, Sra, Or, And,
    Addw, Subw, Sllw, Srlw, Sraw,
    Mul, Mulh, Mulhsu, Mulhu, Div, Divu, Rem, Remu,
    Mulw, Divw, Divuw, Remw, Remuw,
    Ecall, Ebreak, Fence,
    Unknown,
}

impl Mnemonic {
    pub fn text(self) -> &'static str {
        use Mnemonic::*;
        match self {
            Lui => "lui", Auipc => "auipc", Jal => "jal", Jalr => "jalr",
            Beq => "beq", Bne => "bne", Blt => "blt", Bge => "bge",
            Bltu => "bltu", Bgeu => "bgeu",
            Lb => "lb", Lh => "lh", Lw => "lw", Ld => "ld",
            Lbu => "lbu", Lhu => "lhu", Lwu => "lwu",
            Sb => "sb", Sh => "sh", Sw => "sw", Sd => "sd",
            Addi => "addi", Slti => "slti", Sltiu => "sltiu", Xori => "xori",
            Ori => "ori", Andi => "andi", Slli => "slli", Srli => "srli", Srai => "srai",
            Addiw => "addiw", Slliw => "slliw", Srliw => "srliw", Sraiw => "sraiw",
            Add => "add", Sub => "sub", Sll => "sll", Slt => "slt", Sltu => "sltu",
            Xor => "xor", Srl => "srl", Sra => "sra", Or => "or", And => "and",
            Addw => "addw", Subw => "subw", Sllw => "sllw", Srlw => "srlw", Sraw => "sraw",
            Mul => "mul", Mulh => "mulh", Mulhsu => "mulhsu", Mulhu => "mulhu",
            Div => "div", Divu => "divu", Rem => "rem", Remu => "remu",
            Mulw => "mulw", Divw => "divw", Divuw => "divuw", Remw => "remw", Remuw => "remuw",
            Ecall => "ecall", Ebreak => "ebreak", Fence => "fence",
            Unknown => "<unknown>",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub addr: u64,
    pub raw: u32,
    pub mn: Mnemonic,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    R,
    I,
    Shift,
    Load,
    S,
    B,
    U,
    J,
    Sys,
}

fn format_of(mn: Mnemonic) -> Format {
    use Mnemonic::*;
    match mn {
        Lui | Auipc => Format::U,
        Jal => Format::J,
        Beq | Bne | Blt | Bge | Bltu | Bgeu => Format::B,
        Lb | Lh | Lw | Ld | Lbu | Lhu | Lwu | Jalr => Format::Load,
        Sb | Sh | Sw | Sd => Format::S,
        Slli | Srli | Srai | Slliw | Srliw | Sraiw => Format::Shift,
        Addi | Slti | Sltiu | Xori | Ori | Andi | Addiw => Format::I,
        Ecall | Ebreak | Fence | Unknown => Format::Sys,
        _ => Format::R,
    }
}

fn sext(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn imm_i(raw: u32) -> i64 {
    sext((raw >> 20) as u64, 12)
}

fn imm_s(raw: u32) -> i64 {
    sext((((raw >> 25) << 5) | ((raw >> 7) & 0x1f)) as u64, 12)
}

fn imm_b(raw: u32) -> i64 {
    let v = (((raw >> 31) & 1) << 12)
        | (((raw >> 7) & 1) << 11)
        | (((raw >> 25) & 0x3f) << 5)
        | (((raw >> 8) & 0xf) << 1);
    sext(v as u64, 13)
}

fn imm_u(raw: u32) -> i64 {
    (raw & 0xffff_f000) as i32 as i64
}

fn imm_j(raw: u32) -> i64 {
    let v = (((raw >> 31) & 1) << 20)
        | (((raw >> 12) & 0xff) << 12)
        | (((raw >> 20) & 1) << 11)
        | (((raw >> 21) & 0x3ff) << 1);
    sext(v as u64, 21)
}

pub fn decode(addr: u64, raw: u32) -> Insn {
    use Mnemonic::*;

    let opcode = raw & 0x7f;
    let rd = ((raw >> 7) & 0x1f) as u8;
    let funct3 = (raw >> 12) & 0x7;
    let rs1 = ((raw >> 15) & 0x1f) as u8;
    let rs2 = ((raw >> 20) & 0x1f) as u8;
    let funct7 = raw >> 25;

    let unknown = Insn { addr, raw, mn: Unknown, rd: 0, rs1: 0, rs2: 0, imm: 0 };

    let (mn, imm) = match opcode {
        0b0110111 => (Lui, imm_u(raw)),
        0b0010111 => (Auipc, imm_u(raw)),
        0b1101111 => (Jal, imm_j(raw)),
        0b1100111 if funct3 == 0 => (Jalr, imm_i(raw)),
        0b1100011 => {
            let mn = match funct3 {
                0b000 => Beq,
                0b001 => Bne,
                0b100 => Blt,
                0b101 => Bge,
                0b110 => Bltu,
                0b111 => Bgeu,
                _ => return unknown,
            };
            (mn, imm_b(raw))
        }
        0b0000011 => {
            let mn = match funct3 {
                0b000 => Lb,
                0b001 => Lh,
                0b010 => Lw,
                0b011 => Ld,
                0b100 => Lbu,
                0b101 => Lhu,
                0b110 => Lwu,
                _ => return unknown,
            };
            (mn, imm_i(raw))
        }
        0b0100011 => {
            let mn = match funct3 {
                0b000 => Sb,
                0b001 => Sh,
                0b010 => Sw,
                0b011 => Sd,
                _ => return unknown,
            };
            (mn, imm_s(raw))
        }
        0b0010011 => match funct3 {
            0b000 => (Addi, imm_i(raw)),
            0b010 => (Slti, imm_i(raw)),
            0b011 => (Sltiu, imm_i(raw)),
            0b100 => (Xori, imm_i(raw)),
            0b110 => (Ori, imm_i(raw)),
            0b111 => (Andi, imm_i(raw)),
            // RV64 shifts use a 6-bit shamt, so only funct7's top 6 bits
            // discriminate srli/srai.
            0b001 if funct7 >> 1 == 0 => (Slli, ((raw >> 20) & 0x3f) as i64),
            0b101 if funct7 >> 1 == 0b000000 => (Srli, ((raw >> 20) & 0x3f) as i64),
            0b101 if funct7 >> 1 == 0b010000 => (Srai, ((raw >> 20) & 0x3f) as i64),
            _ => return unknown,
        },
        0b0011011 => match (funct3, funct7) {
            (0b000, _) => (Addiw, imm_i(raw)),
            (0b001, 0b0000000) => (Slliw, rs2 as i64),
            (0b101, 0b0000000) => (Srliw, rs2 as i64),
            (0b101, 0b0100000) => (Sraiw, rs2 as i64),
            _ => return unknown,
        },
        0b0110011 => {
            let mn = match (funct7, funct3) {
                (0b0000000, 0b000) => Add,
                (0b0100000, 0b000) => Sub,
                (0b0000000, 0b001) => Sll,
                (0b0000000, 0b010) => Slt,
                (0b0000000, 0b011) => Sltu,
                (0b0000000, 0b100) => Xor,
                (0b0000000, 0b101) => Srl,
                (0b0100000, 0b101) => Sra,
                (0b0000000, 0b110) => Or,
                (0b0000000, 0b111) => And,
                (0b0000001, 0b000) => Mul,
                (0b0000001, 0b001) => Mulh,
                (0b0000001, 0b010) => Mulhsu,
                (0b0000001, 0b011) => Mulhu,
                (0b0000001, 0b100) => Div,
                (0b0000001, 0b101) => Divu,
                (0b0000001, 0b110) => Rem,
                (0b0000001, 0b111) => Remu,
                _ => return unknown,
            };
            (mn, 0)
        }
        0b0111011 => {
            let mn = match (funct7, funct3) {
                (0b0000000, 0b000) => Addw,
                (0b0100000, 0b000) => Subw,
                (0b0000000, 0b001) => Sllw,
                (0b0000000, 0b101) => Srlw,
                (0b0100000, 0b101) => Sraw,
                (0b0000001, 0b000) => Mulw,
                (0b0000001, 0b100) => Divw,
                (0b0000001, 0b101) => Divuw,
                (0b0000001, 0b110) => Remw,
                (0b0000001, 0b111) => Remuw,
                _ => return unknown,
            };
            (mn, 0)
        }
        0b1110011 => match raw >> 20 {
            0 if rd == 0 && rs1 == 0 && funct3 == 0 => (Ecall, 0),
            1 if rd == 0 && rs1 == 0 && funct3 == 0 => (Ebreak, 0),
            _ => return unknown,
        },
        0b0001111 => (Fence, 0),
        _ => return unknown,
    };

    Insn { addr, raw, mn, rd, rs1, rs2, imm }
}

/// Decodes a contiguous run of 4-byte instructions starting at `base`.
/// Compressed (RVC) instructions are not yet supported and decode as
/// `Unknown`; a trailing partial word is ignored.
pub fn decode_all(base: u64, bytes: &[u8]) -> Vec<Insn> {
    bytes
        .chunks_exact(4)
        .enumerate()
        .map(|(i, w)| {
            let raw = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            decode(base + i as u64 * 4, raw)
        })
        .collect()
}

impl Insn {
    /// The resolved target of a direct jump or conditional branch.
    pub fn branch_target(&self) -> Option<u64> {
        use Mnemonic::*;
        match self.mn {
            Jal | Beq | Bne | Blt | Bge | Bltu | Bgeu => {
                Some(self.addr.wrapping_add(self.imm as u64))
            }
            _ => None,
        }
    }

    /// True if control flow does not simply fall through to the next
    /// instruction (calls return, so they are not terminators).
    pub fn is_block_end(&self) -> bool {
        use Mnemonic::*;
        match self.mn {
            Beq | Bne | Blt | Bge | Bltu | Bgeu => true,
            Jal => self.rd == 0,
            Jalr => self.rd == 0,
            _ => false,
        }
    }

    fn reg(idx: u8) -> &'static str {
        REG_NAMES.get(idx as usize).copied().unwrap_or("?")
    }

    /// Canonical (alias-free) assembly text.
    pub fn disasm(&self) -> String {
        use Mnemonic::*;
        let m = self.mn.text();
        let (rd, rs1, rs2) = (Self::reg(self.rd), Self::reg(self.rs1), Self::reg(self.rs2));
        match format_of(self.mn) {
            Format::U => format!("{m} {rd}, {:#x}", (self.imm as u64 >> 12) & 0xfffff),
            Format::J => format!("{m} {rd}, {:#x}", self.addr.wrapping_add(self.imm as u64)),
            Format::B => {
                format!("{m} {rs1}, {rs2}, {:#x}", self.addr.wrapping_add(self.imm as u64))
            }
            Format::Load => format!("{m} {rd}, {}({rs1})", self.imm),
            Format::S => format!("{m} {rs2}, {}({rs1})", self.imm),
            Format::I => format!("{m} {rd}, {rs1}, {}", self.imm),
            Format::Shift => format!("{m} {rd}, {rs1}, {}", self.imm),
            Format::R => format!("{m} {rd}, {rs1}, {rs2}"),
            Format::Sys => {
                if self.mn == Unknown {
                    format!("<unknown {:#010x}>", self.raw)
                } else {
                    m.to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected encodings below were produced with:
    //   llvm-mc -triple=riscv64 -mattr=+m -show-encoding
    #[test]
    fn decodes_llvm_mc_encodings() {
        let cases: &[(u32, &str)] = &[
            (0x02a50513, "addi a0, a0, 42"),
            (0x00813583, "ld a1, 8(sp)"),
            (0x00b13423, "sd a1, 8(sp)"),
            (0x02b50633, "mul a2, a0, a1"),
            (0x40b50533, "sub a0, a0, a1"),
            (0x0015d59b, "srliw a1, a1, 1"),
            (0x12345537, "lui a0, 0x12345"),
            (0x00000073, "ecall"),
            (0x4035d513, "srai a0, a1, 3"),
            (0x00c58533, "add a0, a1, a2"),
        ];
        for &(raw, expected) in cases {
            assert_eq!(decode(0, raw).disasm(), expected, "raw={raw:#010x}");
        }
    }

    #[test]
    fn branch_targets_are_pc_relative() {
        // From the sum.o fixture: at 0x8, `blt a0, t1, 0x18`.
        let insn = decode(0x8, 0x00654863);
        assert_eq!(insn.mn, Mnemonic::Blt);
        assert_eq!(insn.branch_target(), Some(0x18));
        // At 0x14, `jal zero, 0x8` (backwards).
        let insn = decode(0x14, 0xff5ff06f);
        assert_eq!(insn.mn, Mnemonic::Jal);
        assert_eq!(insn.branch_target(), Some(0x8));
        assert!(insn.is_block_end());
    }

    #[test]
    fn garbage_decodes_to_unknown_not_panic() {
        for raw in [0u32, 0xffff_ffff, 0xdead_beef, 0x0000_0001] {
            let _ = decode(0, raw).disasm();
        }
    }
}
