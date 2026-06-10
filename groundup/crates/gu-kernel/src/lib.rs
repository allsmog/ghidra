//! The analysis kernel: a demand-driven, dependency-tracked query engine
//! over a loaded binary plus a user-editable model.
//!
//! Every derived artifact (function list, decoded instructions, lifted IR,
//! annotated listing) is a *query*. Each cached result records which inputs
//! it read and at what revision; when an input changes, only queries that
//! depend on it are recomputed. Renaming a function therefore re-renders
//! listings but never re-decodes or re-lifts anything.
//!
//! This is a deliberately small implementation of the idea — fixed
//! dependency sets, no early cutoff, no parallelism — but the shape is the
//! one that scales (see salsa / rust-analyzer, and rev.ng's incremental
//! pipeline). See ARCHITECTURE.md.

#![forbid(unsafe_code)]

use gu_elf::{Elf, ElfError};
use gu_ir::LiftedFn;
use gu_rv64::{decode_all, lift_function, Insn, Mnemonic};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Write as _;

#[derive(Debug)]
pub enum KernelError {
    Elf(ElfError),
    NoSuchFunction(u64),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Elf(e) => write!(f, "loader: {e}"),
            KernelError::NoSuchFunction(addr) => write!(f, "no function at {addr:#x}"),
        }
    }
}

impl std::error::Error for KernelError {}

impl From<ElfError> for KernelError {
    fn from(e: ElfError) -> Self {
        KernelError::Elf(e)
    }
}

pub type Result<T> = std::result::Result<T, KernelError>;

/// The user-editable side of a project: everything the analyst asserts on
/// top of the binary. Serializes to a line-oriented text format so projects
/// diff and merge like source code.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Model {
    names: BTreeMap<u64, String>,
}

impl Model {
    pub fn name_for(&self, addr: u64) -> Option<&str> {
        self.names.get(&addr).map(String::as_str)
    }

    pub fn to_text(&self) -> String {
        let mut out = String::from("# groundup model v0\n");
        for (addr, name) in &self.names {
            let _ = writeln!(out, "name {addr:#x} {name}");
        }
        out
    }

    pub fn from_text(text: &str) -> Model {
        let mut model = Model::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some("name"), Some(addr), Some(name)) =
                (parts.next(), parts.next(), parts.next())
            {
                let addr = addr.strip_prefix("0x").unwrap_or(addr);
                if let Ok(addr) = u64::from_str_radix(addr, 16) {
                    model.names.insert(addr, name.to_string());
                }
            }
        }
        model
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncInfo {
    pub entry: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Query {
    Functions,
    Insns(u64),
    Lifted(u64),
    Listing(u64),
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Functions => write!(f, "functions()"),
            Query::Insns(a) => write!(f, "insns({a:#x})"),
            Query::Lifted(a) => write!(f, "lifted({a:#x})"),
            Query::Listing(a) => write!(f, "listing({a:#x})"),
        }
    }
}

/// Inputs a query can depend on. The granularity here decides how much
/// invalidation over-approximates; finer-grained deps are future work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dep {
    Binary,
    Names,
}

#[derive(Clone)]
enum Output {
    Functions(Vec<FuncInfo>),
    Insns(Vec<Insn>),
    Lifted(LiftedFn),
    Listing(String),
}

struct CacheEntry {
    deps: Vec<(Dep, u64)>,
    value: Output,
}

pub struct Kernel {
    binary: Vec<u8>,
    rev_binary: u64,
    rev_names: u64,
    model: Model,
    cache: HashMap<Query, CacheEntry>,
    log: Vec<String>,
}

impl Kernel {
    pub fn new(binary: Vec<u8>) -> Kernel {
        Kernel {
            binary,
            rev_binary: 1,
            rev_names: 1,
            model: Model::default(),
            cache: HashMap::new(),
            log: Vec::new(),
        }
    }

    // ---- input mutation: bump the revision of exactly what changed ----

    pub fn set_function_name(&mut self, entry: u64, name: &str) {
        self.model.names.insert(entry, name.to_string());
        self.rev_names += 1;
    }

    pub fn load_model(&mut self, model: Model) {
        if model != self.model {
            self.model = model;
            self.rev_names += 1;
        }
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    /// Drains the hit/recompute log (used by tests and the CLI demo).
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    fn rev_of(&self, dep: Dep) -> u64 {
        match dep {
            Dep::Binary => self.rev_binary,
            Dep::Names => self.rev_names,
        }
    }

    /// A cached result is reusable iff every input it read is unchanged.
    fn lookup(&mut self, q: &Query) -> Option<Output> {
        let entry = self.cache.get(q)?;
        if entry.deps.iter().all(|&(d, r)| self.rev_of(d) == r) {
            self.log.push(format!("cached   {q}"));
            Some(entry.value.clone())
        } else {
            None
        }
    }

    fn store(&mut self, q: Query, deps: &[Dep], value: Output) {
        self.log.push(format!("computed {q}"));
        let deps = deps.iter().map(|&d| (d, self.rev_of(d))).collect();
        self.cache.insert(q, CacheEntry { deps, value });
    }

    // ---- queries ----

    pub fn functions(&mut self) -> Result<Vec<FuncInfo>> {
        if let Some(Output::Functions(v)) = self.lookup(&Query::Functions) {
            return Ok(v);
        }
        let elf = Elf::parse(&self.binary)?;
        let funcs: Vec<FuncInfo> = elf
            .function_symbols()
            .iter()
            .map(|s| FuncInfo { entry: s.value, name: s.name.clone(), size: s.size })
            .collect();
        self.store(Query::Functions, &[Dep::Binary], Output::Functions(funcs.clone()));
        Ok(funcs)
    }

    pub fn insns(&mut self, entry: u64) -> Result<Vec<Insn>> {
        if let Some(Output::Insns(v)) = self.lookup(&Query::Insns(entry)) {
            return Ok(v);
        }
        let elf = Elf::parse(&self.binary)?;
        let sym = elf
            .function_symbols()
            .into_iter()
            .find(|s| s.value == entry)
            .ok_or(KernelError::NoSuchFunction(entry))?;
        let (body, base) = elf.function_body(sym)?;
        let insns = decode_all(base, body);
        self.store(Query::Insns(entry), &[Dep::Binary], Output::Insns(insns.clone()));
        Ok(insns)
    }

    pub fn lifted(&mut self, entry: u64) -> Result<LiftedFn> {
        if let Some(Output::Lifted(v)) = self.lookup(&Query::Lifted(entry)) {
            return Ok(v);
        }
        let symbol_name = self
            .functions()?
            .into_iter()
            .find(|f| f.entry == entry)
            .ok_or(KernelError::NoSuchFunction(entry))?
            .name;
        let insns = self.insns(entry)?;
        let lifted = lift_function(&symbol_name, &insns);
        self.store(Query::Lifted(entry), &[Dep::Binary], Output::Lifted(lifted.clone()));
        Ok(lifted)
    }

    /// Annotated disassembly: model names override symbol names, and direct
    /// call sites are annotated with the callee's current name. This is the
    /// only query that depends on the model, so renames invalidate exactly
    /// the listings.
    pub fn listing(&mut self, entry: u64) -> Result<String> {
        if let Some(Output::Listing(v)) = self.lookup(&Query::Listing(entry)) {
            return Ok(v);
        }
        let funcs = self.functions()?;
        let info = funcs
            .iter()
            .find(|f| f.entry == entry)
            .ok_or(KernelError::NoSuchFunction(entry))?
            .clone();
        let insns = self.insns(entry)?;

        let name_of = |addr: u64| -> Option<String> {
            if let Some(n) = self.model.name_for(addr) {
                return Some(n.to_string());
            }
            funcs.iter().find(|f| f.entry == addr).map(|f| f.name.clone())
        };

        let display = name_of(entry).unwrap_or_else(|| info.name.clone());
        let mut out = String::new();
        let _ = writeln!(out, "{display} @ {entry:#x} ({} bytes):", info.size);
        for insn in &insns {
            let mut line = format!("  {:#06x}: {:08x}  {}", insn.addr, insn.raw, insn.disasm());
            if insn.mn == Mnemonic::Jal && insn.rd == 1 {
                if let Some(callee) = insn.branch_target().and_then(name_of) {
                    let _ = write!(line, "   # call {callee}");
                }
            }
            out.push_str(&line);
            out.push('\n');
        }
        self.store(Query::Listing(entry), &[Dep::Binary, Dep::Names], Output::Listing(out.clone()));
        Ok(out)
    }
}
