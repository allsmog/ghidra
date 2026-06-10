//! The analysis kernel: a demand-driven, dependency-tracked query engine
//! over a loaded binary plus a user-editable model.
//!
//! Every derived artifact (function list, decoded instructions, lifted IR,
//! annotated listing) is a *query*. The engine is salsa-style:
//!
//! - **Dynamic dependency capture.** While a query executes, every input it
//!   reads and every sub-query it asks is recorded. Nothing declares its
//!   dependencies up front, so they are exactly what was actually read.
//! - **Fine-grained inputs.** Each function name is its own input key, so
//!   renaming one function invalidates only the listings that mention it —
//!   not every listing in the program.
//! - **Early cutoff.** If a query re-executes but produces a value equal to
//!   its previous one, its `changed_at` revision is not bumped, and queries
//!   that depend on it are not recomputed. Setting an input to the value it
//!   already has is a no-op entirely.
//!
//! Still deliberately small: single-threaded, no cycle recovery (the query
//! graph here is acyclic by construction), errors are not memoized.
//! See ARCHITECTURE.md for where this goes next.

#![forbid(unsafe_code)]

mod discover;
mod jumptable;

use gu_elf::{Elf, ElfError};
use gu_ir::LiftedFn;
use gu_rv64::{decode_all, lift_function, Insn, Mnemonic};
use gu_ssa::SsaProgram;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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

    pub fn set_name(&mut self, addr: u64, name: &str) {
        self.names.insert(addr, name.to_string());
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
    Ssa(u64),
    OptSsa(u64),
    /// Interprocedural parameter count per function, by call-graph fixpoint.
    Arities,
    Decompile(u64),
    /// The name an address should display as: model override, else symbol.
    /// A query of its own so that redundant model edits get early-cutoff.
    DisplayName(u64),
    Listing(u64),
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Query::Functions => write!(f, "functions()"),
            Query::Insns(a) => write!(f, "insns({a:#x})"),
            Query::Lifted(a) => write!(f, "lifted({a:#x})"),
            Query::Ssa(a) => write!(f, "ssa({a:#x})"),
            Query::OptSsa(a) => write!(f, "opt_ssa({a:#x})"),
            Query::Arities => write!(f, "arities()"),
            Query::Decompile(a) => write!(f, "decompile({a:#x})"),
            Query::DisplayName(a) => write!(f, "display_name({a:#x})"),
            Query::Listing(a) => write!(f, "listing({a:#x})"),
        }
    }
}

/// An input cell. Each carries its own revision, which is what makes
/// invalidation fine-grained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum InputKey {
    Binary,
    /// The model's name override for one address.
    Name(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DepKey {
    Input(InputKey),
    Query(Query),
}

#[derive(Clone, PartialEq)]
enum Output {
    Functions(Vec<FuncInfo>),
    Insns(Vec<Insn>),
    Lifted(LiftedFn),
    Ssa(SsaProgram),
    Arities(HashMap<u64, usize>),
    Name(Option<String>),
    Listing(String),
    Decompiled(String),
}

struct Memo {
    value: Output,
    /// Everything this query read last time it executed, in read order.
    deps: Vec<DepKey>,
    /// Last revision at which this memo was confirmed up to date.
    verified_at: u64,
    /// Last revision at which the value actually changed (early cutoff
    /// keeps this old when a re-execution produces an equal value).
    changed_at: u64,
}

pub struct Kernel {
    binary: Vec<u8>,
    model: Model,
    /// Global revision counter, bumped whenever any input actually changes.
    revision: u64,
    /// Per-input change stamps. Names absent here have never been set and
    /// count as changed at revision 0.
    name_changed_at: HashMap<u64, u64>,
    memos: HashMap<Query, Memo>,
    /// Dependency-capture frames for the queries currently executing.
    active: Vec<Vec<DepKey>>,
    log: Vec<String>,
}

impl Kernel {
    pub fn new(binary: Vec<u8>) -> Kernel {
        Kernel {
            binary,
            model: Model::default(),
            revision: 1,
            name_changed_at: HashMap::new(),
            memos: HashMap::new(),
            active: Vec::new(),
            log: Vec::new(),
        }
    }

    // ---- inputs: each set bumps only the revision of what changed ----

    pub fn set_function_name(&mut self, entry: u64, name: &str) {
        if self.model.name_for(entry) == Some(name) {
            return; // input-level cutoff: writing the same value is a no-op
        }
        self.model.set_name(entry, name);
        self.revision += 1;
        self.name_changed_at.insert(entry, self.revision);
    }

    pub fn load_model(&mut self, model: Model) {
        let keys: BTreeSet<u64> =
            self.model.names.keys().chain(model.names.keys()).copied().collect();
        let changed: Vec<u64> = keys
            .into_iter()
            .filter(|k| self.model.names.get(k) != model.names.get(k))
            .collect();
        if changed.is_empty() {
            return;
        }
        self.revision += 1;
        for k in changed {
            self.name_changed_at.insert(k, self.revision);
        }
        self.model = model;
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    /// Drains the hit/recompute log (used by tests and the CLI demo).
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    fn input_changed_at(&self, key: InputKey) -> u64 {
        match key {
            InputKey::Binary => 1, // set at construction, immutable after
            InputKey::Name(addr) => self.name_changed_at.get(&addr).copied().unwrap_or(0),
        }
    }

    // ---- dependency capture ----

    fn record_dep(&mut self, dep: DepKey) {
        if let Some(frame) = self.active.last_mut() {
            if !frame.contains(&dep) {
                frame.push(dep);
            }
        }
    }

    /// Tracked read of a model name. Recording the read even when the name
    /// is absent is what makes *adding* a name later invalidate correctly.
    fn read_name(&mut self, addr: u64) -> Option<String> {
        self.record_dep(DepKey::Input(InputKey::Name(addr)));
        self.model.name_for(addr).map(str::to_string)
    }

    fn read_binary(&mut self) {
        self.record_dep(DepKey::Input(InputKey::Binary));
    }

    // ---- the engine ----

    /// Fetch a query result, reusing the memo when every dependency is
    /// verifiably unchanged.
    fn get(&mut self, q: &Query) -> Result<Output> {
        self.record_dep(DepKey::Query(q.clone()));
        if self.memos.contains_key(q) && self.validate(q)? {
            self.log.push(format!("cached   {q}"));
            return Ok(self.memos[q].value.clone());
        }
        self.execute(q)
    }

    /// Is the memo for `q` still up to date? May recursively validate or
    /// re-execute dependency queries, but never re-executes `q` itself.
    fn validate(&mut self, q: &Query) -> Result<bool> {
        let (verified_at, deps) = {
            let m = &self.memos[q];
            if m.verified_at == self.revision {
                return Ok(true);
            }
            (m.verified_at, m.deps.clone())
        };
        for dep in deps {
            let changed = match dep {
                DepKey::Input(k) => self.input_changed_at(k) > verified_at,
                DepKey::Query(dq) => self.maybe_changed_after(&dq, verified_at)?,
            };
            if changed {
                return Ok(false);
            }
        }
        if let Some(m) = self.memos.get_mut(q) {
            m.verified_at = self.revision;
        }
        Ok(true)
    }

    /// Has `q`'s *value* changed since revision `rev`? This is where early
    /// cutoff happens: a dependency may re-execute, produce an equal value,
    /// and report "unchanged" to whoever asked.
    fn maybe_changed_after(&mut self, q: &Query, rev: u64) -> Result<bool> {
        if self.memos.contains_key(q) && self.validate(q)? {
            return Ok(self.memos[q].changed_at > rev);
        }
        self.execute(q)?;
        Ok(self.memos[q].changed_at > rev)
    }

    fn execute(&mut self, q: &Query) -> Result<Output> {
        self.active.push(Vec::new());
        let result = self.compute(q);
        let deps = self.active.pop().expect("frame pushed above");
        let value = result?;

        let changed_at = match self.memos.get(q) {
            Some(old) if old.value == value => {
                self.log.push(format!("computed {q} (value unchanged)"));
                old.changed_at
            }
            _ => {
                self.log.push(format!("computed {q}"));
                self.revision
            }
        };
        self.memos.insert(
            q.clone(),
            Memo { value: value.clone(), deps, verified_at: self.revision, changed_at },
        );
        Ok(value)
    }

    // ---- the queries themselves ----

    fn compute(&mut self, q: &Query) -> Result<Output> {
        match *q {
            Query::Functions => {
                self.read_binary();
                let elf = Elf::parse(&self.binary)?;
                let funcs: Vec<FuncInfo> = if elf.header.etype == gu_elf::ET_REL {
                    // Relocatable objects: call targets are unrelocated, so
                    // symbols are the only trustworthy source.
                    elf.function_symbols()
                        .iter()
                        .map(|s| FuncInfo { entry: s.value, name: s.name.clone(), size: s.size })
                        .collect()
                } else {
                    discover::discover(&elf)
                };
                Ok(Output::Functions(funcs))
            }
            Query::Insns(entry) => {
                self.read_binary();
                let elf = Elf::parse(&self.binary)?;
                if elf.header.etype == gu_elf::ET_REL {
                    let sym = elf
                        .function_symbols()
                        .into_iter()
                        .find(|s| s.value == entry)
                        .ok_or(KernelError::NoSuchFunction(entry))?;
                    let (body, base) = elf.function_body(sym)?;
                    Ok(Output::Insns(decode_all(base, body)))
                } else {
                    // Linked binary: extents come from discovery, bytes
                    // from the program headers.
                    let info = self
                        .functions()?
                        .into_iter()
                        .find(|f| f.entry == entry)
                        .ok_or(KernelError::NoSuchFunction(entry))?;
                    let elf = Elf::parse(&self.binary)?;
                    let body = elf.bytes_at_vaddr(entry, info.size)?;
                    Ok(Output::Insns(decode_all(entry, body)))
                }
            }
            Query::Lifted(entry) => {
                let symbol_name = self
                    .functions()?
                    .into_iter()
                    .find(|f| f.entry == entry)
                    .ok_or(KernelError::NoSuchFunction(entry))?
                    .name;
                let insns = self.insns(entry)?;
                Ok(Output::Lifted(lift_function(&symbol_name, &insns)))
            }
            Query::DisplayName(addr) => {
                let name = match self.read_name(addr) {
                    Some(n) => Some(n),
                    // Fallback to the symbol name; recorded as a dependency
                    // on functions() via the tracked sub-query call.
                    None => self
                        .functions()?
                        .into_iter()
                        .find(|f| f.entry == addr)
                        .map(|f| f.name),
                };
                Ok(Output::Name(name))
            }
            Query::Ssa(entry) => {
                let lifted = self.lifted(entry)?;
                Ok(Output::Ssa(gu_ssa::build(&lifted)))
            }
            Query::OptSsa(entry) => {
                let ssa = self.ssa(entry)?;
                Ok(Output::Ssa(gu_ssa::optimize(&ssa)))
            }
            Query::Arities => {
                // Interprocedural parameter-count fixpoint over the call
                // graph. A call reads as many arguments as its callee takes,
                // which can make a forwarded incoming argument a parameter of
                // the caller too — so arities are mutually dependent. Arity
                // is monotone and bounded by 8, so this converges.
                let entries: Vec<u64> = self.functions()?.iter().map(|f| f.entry).collect();
                let mut ssas: HashMap<u64, SsaProgram> = HashMap::new();
                for e in &entries {
                    ssas.insert(*e, self.opt_ssa(*e)?);
                }
                let mut arity: HashMap<u64, usize> =
                    entries.iter().map(|&e| (e, 0)).collect();
                loop {
                    let mut changed = false;
                    for e in &entries {
                        let lookup = |t: u64| arity.get(&t).copied().unwrap_or(0);
                        let new = gu_decompile::arg_count(&ssas[e], &lookup);
                        if new != arity[e] {
                            arity.insert(*e, new);
                            changed = true;
                        }
                    }
                    if !changed {
                        break;
                    }
                }
                Ok(Output::Arities(arity))
            }
            Query::Decompile(entry) => {
                let opt = self.opt_ssa(entry)?;
                // Resolve call targets to symbol/discovered names. Using
                // functions() (not model overrides) keeps decompilation
                // byte-dependent, so it caches across renames.
                let names: HashMap<u64, String> =
                    self.functions()?.into_iter().map(|f| (f.entry, f.name)).collect();
                let arities = self.arities()?;
                let text = gu_decompile::decompile(
                    &opt,
                    &|a| names.get(&a).cloned(),
                    &|a| arities.get(&a).copied().unwrap_or(0),
                );
                Ok(Output::Decompiled(text))
            }
            Query::Listing(entry) => Ok(Output::Listing(self.compute_listing(entry)?)),
        }
    }

    /// Annotated disassembly: model names override symbol names, and direct
    /// call sites are annotated with the callee's current name. Name reads
    /// go through `read_name`, so a listing depends on exactly the names it
    /// displays — renaming anything else leaves it untouched.
    fn compute_listing(&mut self, entry: u64) -> Result<String> {
        let funcs = self.functions()?;
        let info = funcs
            .iter()
            .find(|f| f.entry == entry)
            .ok_or(KernelError::NoSuchFunction(entry))?
            .clone();
        let insns = self.insns(entry)?;

        // Resolve any jump tables so indirect jumps can be annotated with
        // their case targets.
        self.read_binary();
        let jump_targets: std::collections::HashMap<u64, Vec<u64>> = {
            let elf = Elf::parse(&self.binary)?;
            jumptable::resolve(&elf, &insns).into_iter().collect()
        };

        let call_target = |insn: &Insn| -> Option<u64> {
            (insn.mn == Mnemonic::Jal && insn.rd == 1)
                .then(|| insn.branch_target())
                .flatten()
        };

        // Tracked name resolution for this function and every callee. Going
        // through the display_name query means a listing depends on exactly
        // the names it shows, with early cutoff on redundant edits.
        let mut wanted: Vec<u64> = vec![entry];
        wanted.extend(insns.iter().filter_map(&call_target));
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        for addr in wanted {
            if let Some(n) = self.display_name(addr)? {
                names.insert(addr, n);
            }
        }

        let display = names.get(&entry).cloned().unwrap_or_else(|| info.name.clone());
        let mut out = String::new();
        let _ = writeln!(out, "{display} @ {entry:#x} ({} bytes):", info.size);
        for insn in &insns {
            let mut line = format!("  {:#06x}: {:08x}  {}", insn.addr, insn.raw, insn.disasm());
            if let Some(callee) = call_target(insn).and_then(|t| names.get(&t)) {
                let _ = write!(line, "   # call {callee}");
            }
            if let Some(targets) = jump_targets.get(&insn.addr) {
                let cases: Vec<String> = targets.iter().map(|t| format!("{t:#x}")).collect();
                let _ = write!(line, "   # switch -> {}", cases.join(", "));
            }
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    // ---- public API: typed wrappers over the engine ----

    pub fn functions(&mut self) -> Result<Vec<FuncInfo>> {
        match self.get(&Query::Functions)? {
            Output::Functions(v) => Ok(v),
            _ => panic!("functions() produced wrong output kind"),
        }
    }

    pub fn insns(&mut self, entry: u64) -> Result<Vec<Insn>> {
        match self.get(&Query::Insns(entry))? {
            Output::Insns(v) => Ok(v),
            _ => panic!("insns() produced wrong output kind"),
        }
    }

    pub fn lifted(&mut self, entry: u64) -> Result<LiftedFn> {
        match self.get(&Query::Lifted(entry))? {
            Output::Lifted(v) => Ok(v),
            _ => panic!("lifted() produced wrong output kind"),
        }
    }

    pub fn ssa(&mut self, entry: u64) -> Result<SsaProgram> {
        match self.get(&Query::Ssa(entry))? {
            Output::Ssa(v) => Ok(v),
            _ => panic!("ssa() produced wrong output kind"),
        }
    }

    pub fn opt_ssa(&mut self, entry: u64) -> Result<SsaProgram> {
        match self.get(&Query::OptSsa(entry))? {
            Output::Ssa(v) => Ok(v),
            _ => panic!("opt_ssa() produced wrong output kind"),
        }
    }

    pub fn arities(&mut self) -> Result<HashMap<u64, usize>> {
        match self.get(&Query::Arities)? {
            Output::Arities(v) => Ok(v),
            _ => panic!("arities() produced wrong output kind"),
        }
    }

    pub fn decompile(&mut self, entry: u64) -> Result<String> {
        match self.get(&Query::Decompile(entry))? {
            Output::Decompiled(v) => Ok(v),
            _ => panic!("decompile() produced wrong output kind"),
        }
    }

    pub fn display_name(&mut self, addr: u64) -> Result<Option<String>> {
        match self.get(&Query::DisplayName(addr))? {
            Output::Name(v) => Ok(v),
            _ => panic!("display_name() produced wrong output kind"),
        }
    }

    pub fn listing(&mut self, entry: u64) -> Result<String> {
        match self.get(&Query::Listing(entry))? {
            Output::Listing(v) => Ok(v),
            _ => panic!("listing() produced wrong output kind"),
        }
    }
}
