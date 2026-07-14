//! Jump-table resolution: a small value-set analysis that recognizes the
//! switch-dispatch pattern and reads the target table out of the binary.
//!
//! The canonical RISC-V pattern (after linking) is:
//!
//! ```text
//!   auipc t0, hi ; addi t0, t0, lo   # t0 = &table   (a constant address)
//!   slli  t1, idx, 3                 # t1 = idx * 8   (unknown index)
//!   add   t0, t0, t1                 # t0 = &table[idx]
//!   ld    t0, 0(t0)                  # t0 = table[idx]
//!   jalr  zero, 0(t0)               # goto *t0
//! ```
//!
//! A forward abstract interpretation tracks each register as a constant
//! address, a table pointer (`base + unknown`), or a value loaded from a
//! table. When an indirect jump targets a table-loaded value, the table is
//! read from the binary: consecutive pointer-sized entries are accepted
//! while they point into an executable segment.

use gu_elf::Elf;
use gu_rv64::{Insn, Mnemonic};

/// Defensive cap on table entries read from the binary.
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy, PartialEq)]
enum Val {
    Unknown,
    /// A known absolute address/constant.
    Const(i64),
    /// `base + <index in register r>` — a pointer into a table at `base`.
    TablePtr { base: i64, index: u16 },
    /// A value loaded from the table beginning at `base`, indexed by `r`.
    TableElem { base: i64, index: u16 },
}

/// A resolved jump table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// Address of the indirect jump instruction.
    pub jump_addr: u64,
    /// Case target addresses, in table order.
    pub targets: Vec<u64>,
    /// The register holding the switch index (before scaling), if recovered.
    pub index_reg: Option<u16>,
}

/// Resolves every indirect jump in `insns` that matches the jump-table
/// pattern.
pub fn resolve(elf: &Elf, insns: &[Insn]) -> Vec<JumpTable> {
    let mut regs = [Val::Unknown; 32];
    regs[0] = Val::Const(0); // x0 is hardwired to zero
    // The pre-scaling source register of a shift/multiply, so the recovered
    // index is the original variable (`a0`), not the scaled temporary.
    let mut scale_src = [None; 32];
    let mut out = Vec::new();

    for insn in insns {
        use Mnemonic::*;
        let rd = insn.rd as usize;
        let rs1 = regs[insn.rs1 as usize];
        let rs2 = regs[insn.rs2 as usize];

        // An indirect jump (jalr zero, 0(rs1), rs1 != ra) through a
        // table-loaded value: read the table.
        if insn.mn == Jalr && insn.rd == 0 && insn.imm == 0 && insn.rs1 != 1 {
            if let Val::TableElem { base, index } = rs1 {
                let targets = read_table(elf, base as u64);
                if !targets.is_empty() {
                    out.push(JumpTable {
                        jump_addr: insn.addr,
                        targets,
                        index_reg: Some(index),
                    });
                }
            }
        }

        let next = match insn.mn {
            Auipc => Val::Const(insn.addr.wrapping_add(insn.imm as u64) as i64),
            Lui => Val::Const(insn.imm),
            Addi => match rs1 {
                Val::Const(c) => Val::Const(c.wrapping_add(insn.imm)),
                _ => Val::Unknown,
            },
            Add => match (rs1, rs2) {
                (Val::Const(a), Val::Const(b)) => Val::Const(a.wrapping_add(b)),
                // base + scaled index  ->  table pointer; recover the index.
                (Val::Const(base), Val::Unknown) => {
                    Val::TablePtr { base, index: orig_index(insn.rs2, &scale_src) }
                }
                (Val::Unknown, Val::Const(base)) => {
                    Val::TablePtr { base, index: orig_index(insn.rs1, &scale_src) }
                }
                _ => Val::Unknown,
            },
            Ld => match rs1 {
                Val::TablePtr { base, index } => {
                    Val::TableElem { base: base.wrapping_add(insn.imm), index }
                }
                _ => Val::Unknown,
            },
            // Anything else clobbers its destination with an unknown value.
            _ => Val::Unknown,
        };

        // Track scaling so the recovered index is the unscaled register.
        if insn.mn == Slli && rd != 0 {
            scale_src[rd] = Some(insn.rs1);
        }

        if rd != 0 && writes_rd(insn.mn) {
            regs[rd] = next;
            if insn.mn != Slli {
                scale_src[rd] = None;
            }
        }
    }
    out
}

/// The original (unscaled) index register: the source of a recorded shift,
/// else the register itself.
fn orig_index(reg: u8, scale_src: &[Option<u8>; 32]) -> u16 {
    scale_src[reg as usize].unwrap_or(reg) as u16
}

/// Reads pointer-sized table entries starting at `base`, accepting each
/// while it points into an executable segment.
fn read_table(elf: &Elf, base: u64) -> Vec<u64> {
    let mut targets = Vec::new();
    for i in 0..MAX_ENTRIES as u64 {
        let Ok(bytes) = elf.bytes_at_vaddr(base + i * 8, 8) else { break };
        let target = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
        if elf.exec_segment_at(target).is_none() {
            break;
        }
        targets.push(target);
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Whether an instruction writes its `rd` register.
fn writes_rd(mn: Mnemonic) -> bool {
    use Mnemonic::*;
    !matches!(
        mn,
        Beq | Bne | Blt | Bge | Bltu | Bgeu
            | Sb | Sh | Sw | Sd
            | Ecall | Ebreak | Fence | Unknown
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gu_rv64::decode_all;

    #[test]
    fn resolves_pc_relative_switch() {
        let data: &[u8] = include_bytes!("../../../fixtures/switch_stripped");
        let elf = Elf::parse(data).expect("fixture parses");
        // Decode the dispatch function's instruction span.
        let entry = elf.header.entry;
        let bytes = elf.bytes_at_vaddr(entry, 0x40).expect("readable");
        let insns = decode_all(entry, bytes);

        let resolved = resolve(&elf, &insns);
        assert_eq!(resolved.len(), 1, "one jump table expected: {resolved:?}");
        let table = &resolved[0];
        assert_eq!(table.jump_addr, entry + 0x1c, "jalr at dispatch+0x1c");
        assert_eq!(table.targets, [0x11158, 0x11160, 0x11168], "case addresses");
        assert_eq!(table.index_reg, Some(10), "switch index is a0 (x10)");
    }

    #[test]
    fn no_table_means_no_resolution() {
        // A plain return is not a jump table.
        let elf_bytes: &[u8] = include_bytes!("../../../fixtures/switch_stripped");
        let elf = Elf::parse(elf_bytes).unwrap();
        let insns = decode_all(0, &0x00008067u32.to_le_bytes()); // jalr zero, 0(ra)
        assert!(resolve(&elf, &insns).is_empty());
    }
}
