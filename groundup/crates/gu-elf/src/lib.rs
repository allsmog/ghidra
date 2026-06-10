//! Zero-dependency, panic-free ELF64 (little-endian) parser.
//!
//! Loaders parse hostile input, so this crate is deliberately hand-rolled:
//! no external dependencies, no unsafe code, and every read is bounds-checked
//! and returns an error instead of panicking on malformed input.

#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    Truncated { at: usize, want: usize },
    BadMagic,
    Unsupported(&'static str),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::Truncated { at, want } => {
                write!(f, "truncated: wanted {want} bytes at offset {at:#x}")
            }
            ElfError::BadMagic => write!(f, "not an ELF file (bad magic)"),
            ElfError::Unsupported(what) => write!(f, "unsupported ELF: {what}"),
        }
    }
}

impl std::error::Error for ElfError {}

pub type Result<T> = std::result::Result<T, ElfError>;

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_RISCV: u16 = 243;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOBITS: u32 = 8;
pub const STT_FUNC: u8 = 2;

fn bytes_at(data: &[u8], at: usize, want: usize) -> Result<&[u8]> {
    let end = at.checked_add(want).ok_or(ElfError::Truncated { at, want })?;
    data.get(at..end).ok_or(ElfError::Truncated { at, want })
}

fn u8_at(data: &[u8], at: usize) -> Result<u8> {
    Ok(bytes_at(data, at, 1)?[0])
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let b = bytes_at(data, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let b = bytes_at(data, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    let b = bytes_at(data, at, 8)?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Reads a NUL-terminated string out of a string table, tolerating a
/// missing terminator at the end of the table.
fn str_at(strtab: &[u8], idx: usize) -> String {
    let Some(tail) = strtab.get(idx..) else {
        return String::new();
    };
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

#[derive(Debug, Clone)]
pub struct Header {
    pub etype: u16,
    pub machine: u16,
    pub entry: u64,
    pub shoff: u64,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub shtype: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub entsize: u64,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub shndx: u16,
}

impl Symbol {
    pub fn is_function(&self) -> bool {
        self.info & 0xf == STT_FUNC
    }
}

#[derive(Debug)]
pub struct Elf<'a> {
    pub data: &'a [u8],
    pub header: Header,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Elf<'a>> {
        if bytes_at(data, 0, 4)? != [0x7f, b'E', b'L', b'F'] {
            return Err(ElfError::BadMagic);
        }
        if u8_at(data, 4)? != 2 {
            return Err(ElfError::Unsupported("only ELF64 is supported"));
        }
        if u8_at(data, 5)? != 1 {
            return Err(ElfError::Unsupported("only little-endian is supported"));
        }

        let header = Header {
            etype: u16_at(data, 16)?,
            machine: u16_at(data, 18)?,
            entry: u64_at(data, 24)?,
            shoff: u64_at(data, 40)?,
            shentsize: u16_at(data, 58)?,
            shnum: u16_at(data, 60)?,
            shstrndx: u16_at(data, 62)?,
        };

        let mut sections = Vec::new();
        if header.shoff != 0 {
            if header.shentsize < 64 {
                return Err(ElfError::Unsupported("section header entry too small"));
            }
            // Cap shnum at what the file could actually hold so a corrupt
            // count can't drive a huge allocation.
            let max_sections = data.len() / 64;
            let shnum = (header.shnum as usize).min(max_sections);
            for i in 0..shnum {
                let off = header.shoff as usize + i * header.shentsize as usize;
                sections.push(Section {
                    name: format!("{}", u32_at(data, off)?), // patched up below
                    shtype: u32_at(data, off + 4)?,
                    flags: u64_at(data, off + 8)?,
                    addr: u64_at(data, off + 16)?,
                    offset: u64_at(data, off + 24)?,
                    size: u64_at(data, off + 32)?,
                    link: u32_at(data, off + 40)?,
                    entsize: u64_at(data, off + 56)?,
                });
            }
            // Resolve section names through the section-header string table.
            if let Some(shstr) = sections.get(header.shstrndx as usize) {
                let strtab =
                    bytes_at(data, shstr.offset as usize, shstr.size as usize).unwrap_or(&[]);
                let name_indices: Vec<usize> = (0..sections.len())
                    .map(|i| {
                        let off = header.shoff as usize + i * header.shentsize as usize;
                        u32_at(data, off).unwrap_or(0) as usize
                    })
                    .collect();
                for (sec, idx) in sections.iter_mut().zip(name_indices) {
                    sec.name = str_at(strtab, idx);
                }
            }
        }

        let mut symbols = Vec::new();
        if let Some(symtab) = sections.iter().find(|s| s.shtype == SHT_SYMTAB) {
            let strtab = sections
                .get(symtab.link as usize)
                .and_then(|s| bytes_at(data, s.offset as usize, s.size as usize).ok())
                .unwrap_or(&[]);
            let count = if symtab.entsize >= 24 {
                symtab.size / symtab.entsize
            } else {
                0
            };
            for i in 0..count {
                let off = (symtab.offset + i * symtab.entsize) as usize;
                symbols.push(Symbol {
                    name: str_at(strtab, u32_at(data, off)? as usize),
                    info: u8_at(data, off + 4)?,
                    shndx: u16_at(data, off + 6)?,
                    value: u64_at(data, off + 8)?,
                    size: u64_at(data, off + 16)?,
                });
            }
        }

        Ok(Elf { data, header, sections, symbols })
    }

    pub fn section_bytes(&self, sec: &Section) -> Result<&'a [u8]> {
        if sec.shtype == SHT_NOBITS {
            return Ok(&[]);
        }
        bytes_at(self.data, sec.offset as usize, sec.size as usize)
    }

    /// Function symbols that live in a real section, in address order.
    pub fn function_symbols(&self) -> Vec<&Symbol> {
        let mut funcs: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| s.is_function() && (s.shndx as usize) < self.sections.len())
            .collect();
        funcs.sort_by_key(|s| s.value);
        funcs
    }

    /// The bytes of a function body and the address its first byte should be
    /// reported at. For relocatable objects `st_value` is section-relative;
    /// for executables it is a virtual address inside the section.
    pub fn function_body(&self, sym: &Symbol) -> Result<(&'a [u8], u64)> {
        let sec = self
            .sections
            .get(sym.shndx as usize)
            .ok_or(ElfError::Unsupported("symbol points outside section table"))?;
        let sec_bytes = self.section_bytes(sec)?;
        let start = if self.header.etype == ET_REL {
            sym.value
        } else {
            sym.value.wrapping_sub(sec.addr)
        } as usize;
        let len = sym.size as usize;
        let end = start.checked_add(len).ok_or(ElfError::Truncated { at: start, want: len })?;
        let body = sec_bytes
            .get(start..end)
            .ok_or(ElfError::Truncated { at: start, want: len })?;
        Ok((body, sym.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert_eq!(Elf::parse(&[]).unwrap_err(), ElfError::Truncated { at: 0, want: 4 });
        assert_eq!(Elf::parse(b"NOPE").unwrap_err(), ElfError::BadMagic);
        let mut almost = vec![0x7f, b'E', b'L', b'F', 1, 1];
        almost.resize(64, 0);
        assert_eq!(
            Elf::parse(&almost).unwrap_err(),
            ElfError::Unsupported("only ELF64 is supported")
        );
    }

    #[test]
    fn parses_fixture() {
        let data: &[u8] = include_bytes!("../../../fixtures/sum.o");
        let elf = Elf::parse(data).expect("fixture should parse");
        assert_eq!(elf.header.machine, EM_RISCV);
        assert_eq!(elf.header.etype, ET_REL);
        assert!(elf.sections.iter().any(|s| s.name == ".text"));

        let funcs = elf.function_symbols();
        let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["sum_to_n", "entry"]);

        let (body, addr) = elf.function_body(funcs[0]).unwrap();
        assert_eq!(addr, 0);
        assert!(!body.is_empty() && body.len() % 4 == 0);
    }

    #[test]
    fn corrupt_section_count_does_not_panic() {
        let mut data: Vec<u8> = include_bytes!("../../../fixtures/sum.o").to_vec();
        data[60] = 0xff; // e_shnum
        data[61] = 0xff;
        let _ = Elf::parse(&data); // must not panic or OOM
    }
}
