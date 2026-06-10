//! `gu` — command-line client for the groundup kernel.
//!
//! In the target architecture this is one of several peer clients of the
//! kernel's API (GUI, CI, scripts); it deliberately contains no analysis
//! logic of its own.

use gu_kernel::Kernel;
use gu_rv64::Rv64Namer;
use std::process::ExitCode;

const USAGE: &str = "\
usage: gu <command> <file.elf> [function]

commands:
  info     ELF header, sections, and function symbols
  disasm   disassemble functions (all, or just [function])
  lift     lift functions to IR and print the CFG
  demo     show incremental recomputation: warm the cache, rename a
           function, and watch what does (and does not) recompute
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, path, func) = match args.as_slice() {
        [cmd, path] => (cmd.as_str(), path.as_str(), None),
        [cmd, path, func] => (cmd.as_str(), path.as_str(), Some(func.as_str())),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("gu: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    match run(cmd, data, func) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gu: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cmd: &str, data: Vec<u8>, func: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "info" => info(&data),
        "disasm" => with_functions(data, func, |k, entry| {
            print!("{}", k.listing(entry)?);
            println!();
            Ok(())
        }),
        "lift" => with_functions(data, func, |k, entry| {
            print!("{}", k.lifted(entry)?.render(&Rv64Namer));
            println!();
            Ok(())
        }),
        "demo" => demo(data),
        other => {
            eprint!("{USAGE}");
            Err(format!("unknown command '{other}'").into())
        }
    }
}

fn info(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let elf = gu_elf::Elf::parse(data)?;
    let h = &elf.header;
    let etype = match h.etype {
        gu_elf::ET_REL => "relocatable",
        gu_elf::ET_EXEC => "executable",
        gu_elf::ET_DYN => "shared object / PIE",
        _ => "other",
    };
    println!("type:    {etype} ({})", h.etype);
    println!("machine: {} ({})", if h.machine == gu_elf::EM_RISCV { "RISC-V" } else { "?" }, h.machine);
    println!("entry:   {:#x}", h.entry);
    println!("\nsections:");
    for s in &elf.sections {
        if !s.name.is_empty() {
            println!("  {:<20} addr {:#010x}  size {:#8x}", s.name, s.addr, s.size);
        }
    }
    println!("\nfunctions:");
    for f in elf.function_symbols() {
        println!("  {:#010x}  {:6} bytes  {}", f.value, f.size, f.name);
    }
    Ok(())
}

fn with_functions(
    data: Vec<u8>,
    func: Option<&str>,
    mut each: impl FnMut(&mut Kernel, u64) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = Kernel::new(data);
    let funcs = kernel.functions()?;
    let selected: Vec<_> = funcs
        .iter()
        .filter(|f| func.is_none_or(|n| f.name == n))
        .map(|f| f.entry)
        .collect();
    if selected.is_empty() {
        return Err(match func {
            Some(n) => format!("no function named '{n}'").into(),
            None => "no function symbols found".into(),
        });
    }
    for entry in selected {
        each(&mut kernel, entry)?;
    }
    Ok(())
}

fn demo(data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let mut k = Kernel::new(data);
    let funcs = k.functions()?;
    let Some(first) = funcs.first().cloned() else {
        return Err("no function symbols found".into());
    };

    println!("== 1. cold cache: compute listings for all functions ==");
    for f in &funcs {
        print!("{}", k.listing(f.entry)?);
        println!();
    }
    print_log(&mut k);

    println!("\n== 2. warm cache: ask again ==");
    for f in &funcs {
        k.listing(f.entry)?;
    }
    print_log(&mut k);

    let new_name = format!("{}_renamed", first.name);
    println!("\n== 3. rename {} -> {} and ask again ==", first.name, new_name);
    k.set_function_name(first.entry, &new_name);
    for f in &funcs {
        print!("{}", k.listing(f.entry)?);
        println!();
    }
    print_log(&mut k);
    println!("note: listings recomputed; decoding was reused from cache.");

    println!("\n== 4. the model (diffable project state) ==");
    print!("{}", k.model().to_text());
    Ok(())
}

fn print_log(k: &mut Kernel) {
    println!("--- query log ---");
    for line in k.take_log() {
        println!("  {line}");
    }
}
