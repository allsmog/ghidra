//! Renders the structured high-level IR as C-like pseudocode.

use crate::hir::{HExpr, HStmt};
use gu_ir::{BinOp, CmpOp, UnOp};
use std::collections::HashSet;
use std::fmt::Write as _;

/// Renders a function. `params` and `decls` are `(c_type, name)` pairs.
pub fn emit(
    name: &str,
    entry: u64,
    ret: &str,
    params: &[(String, String)],
    decls: &[(String, String)],
    body: &[HStmt],
) -> String {
    let mut targeted = HashSet::new();
    collect_goto_targets(body, &mut targeted);

    let param_list = if params.is_empty() {
        "void".to_string()
    } else {
        params.iter().map(|(t, n)| decl(t, n)).collect::<Vec<_>>().join(", ")
    };

    let mut out = String::new();
    let _ = writeln!(out, "// {name} @ {entry:#x}");
    let _ = writeln!(out, "{ret} {name}({param_list}) {{");
    for (ty, n) in decls {
        let _ = writeln!(out, "    {};", decl(ty, n));
    }
    emit_block(body, 1, &targeted, &mut out);
    let _ = writeln!(out, "}}");
    out
}

/// Joins a C type and a name without a stray space after a pointer `*`
/// (`unsigned char *p`, not `unsigned char * p`).
fn decl(ty: &str, name: &str) -> String {
    if ty.ends_with('*') {
        format!("{ty}{name}")
    } else {
        format!("{ty} {name}")
    }
}

/// Variable names appearing in the body, as assignment targets or operands —
/// the set needing local declarations (minus parameters and stack slots).
pub fn referenced_vars(body: &[HStmt]) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |n: &str, names: &mut Vec<String>| {
        if seen.insert(n.to_string()) {
            names.push(n.to_string());
        }
    };
    fn walk_expr(e: &HExpr, f: &mut dyn FnMut(&str)) {
        match e {
            HExpr::Var(n) => f(n),
            HExpr::Bin(_, a, b) | HExpr::Cmp(_, a, b) | HExpr::Index(a, b) => {
                walk_expr(a, f);
                walk_expr(b, f);
            }
            HExpr::Un(_, v) | HExpr::Deref(v) => walk_expr(v, f),
            HExpr::Load { addr, .. } => walk_expr(addr, f),
            HExpr::Const(_) => {}
        }
    }
    fn walk(stmts: &[HStmt], f: &mut dyn FnMut(&str)) {
        for s in stmts {
            match s {
                HStmt::Assign(n, e) => {
                    f(n);
                    walk_expr(e, f);
                }
                HStmt::Store { addr, val, .. } => {
                    walk_expr(addr, f);
                    walk_expr(val, f);
                }
                HStmt::Call { args, .. } => args.iter().for_each(|a| walk_expr(a, f)),
                HStmt::CallIndirect { target, args } => {
                    walk_expr(target, f);
                    args.iter().for_each(|a| walk_expr(a, f));
                }
                HStmt::Return(Some(e)) | HStmt::IndirectJump(e) => walk_expr(e, f),
                HStmt::If { cond, then_body, else_body } => {
                    walk_expr(cond, f);
                    walk(then_body, f);
                    walk(else_body, f);
                }
                HStmt::While { cond, body } => {
                    walk_expr(cond, f);
                    walk(body, f);
                }
                _ => {}
            }
        }
    }
    walk(body, &mut |n| add(n, &mut names));
    names
}

fn collect_goto_targets(stmts: &[HStmt], out: &mut HashSet<u64>) {
    for s in stmts {
        match s {
            HStmt::Goto(t) => {
                out.insert(*t);
            }
            HStmt::If { then_body, else_body, .. } => {
                collect_goto_targets(then_body, out);
                collect_goto_targets(else_body, out);
            }
            HStmt::While { body, .. } => collect_goto_targets(body, out),
            _ => {}
        }
    }
}

fn indent(level: usize) -> String {
    "    ".repeat(level)
}

fn emit_block(stmts: &[HStmt], level: usize, targeted: &HashSet<u64>, out: &mut String) {
    let pad = indent(level);
    for s in stmts {
        match s {
            HStmt::Label(addr) => {
                if targeted.contains(addr) {
                    // Labels sit one indent out, like C.
                    let _ = writeln!(out, "{}loc_{addr:x}:", indent(level.saturating_sub(1)));
                }
            }
            HStmt::Assign(var, e) => {
                let _ = writeln!(out, "{pad}{var} = {};", fmt_expr(e));
            }
            HStmt::Store { addr, val, size } => {
                let _ = writeln!(
                    out,
                    "{pad}*({}*)({}) = {};",
                    c_type(*size),
                    fmt_expr(addr),
                    fmt_expr(val)
                );
            }
            HStmt::Call { name, args } => {
                let _ = writeln!(out, "{pad}{name}({});", fmt_args(args));
            }
            HStmt::CallIndirect { target, args } => {
                let _ = writeln!(out, "{pad}(*{})({});", fmt_expr(target), fmt_args(args));
            }
            HStmt::SysCall => {
                let _ = writeln!(out, "{pad}syscall();");
            }
            HStmt::Return(Some(e)) => {
                let _ = writeln!(out, "{pad}return {};", fmt_expr(e));
            }
            HStmt::Return(None) => {
                let _ = writeln!(out, "{pad}return;");
            }
            HStmt::IndirectJump(e) => {
                let _ = writeln!(out, "{pad}goto *{};", fmt_expr(e));
            }
            HStmt::Goto(t) => {
                let _ = writeln!(out, "{pad}goto loc_{t:x};");
            }
            HStmt::Break => {
                let _ = writeln!(out, "{pad}break;");
            }
            HStmt::Continue => {
                let _ = writeln!(out, "{pad}continue;");
            }
            HStmt::If { cond, then_body, else_body } => {
                let _ = writeln!(out, "{pad}if ({}) {{", fmt_expr(cond));
                emit_block(then_body, level + 1, targeted, out);
                if !else_body.is_empty() {
                    let _ = writeln!(out, "{pad}}} else {{");
                    emit_block(else_body, level + 1, targeted, out);
                }
                let _ = writeln!(out, "{pad}}}");
            }
            HStmt::While { cond, body } => {
                let _ = writeln!(out, "{pad}while ({}) {{", fmt_expr(cond));
                emit_block(body, level + 1, targeted, out);
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }
}

fn fmt_args(args: &[HExpr]) -> String {
    args.iter().map(fmt_expr).collect::<Vec<_>>().join(", ")
}

fn c_type(size: u8) -> &'static str {
    match size {
        1 => "int8_t",
        2 => "int16_t",
        4 => "int32_t",
        _ => "int64_t",
    }
}

fn fmt_expr(e: &HExpr) -> String {
    match e {
        HExpr::Const(i) => {
            if (-9..=9).contains(i) {
                format!("{i}")
            } else if *i < 0 {
                format!("-{:#x}", (*i as i128).unsigned_abs())
            } else {
                format!("{i:#x}")
            }
        }
        HExpr::Var(name) => name.clone(),
        HExpr::Bin(op, a, b) => {
            format!("({} {} {})", fmt_expr(a), bin_sym(*op), fmt_expr(b))
        }
        HExpr::Cmp(op, a, b) => {
            format!("{} {} {}", fmt_expr(a), cmp_sym(*op), fmt_expr(b))
        }
        HExpr::Un(UnOp::Sext32, v) => format!("(int32_t){}", fmt_expr(v)),
        HExpr::Un(UnOp::Zext32, v) => format!("(uint32_t){}", fmt_expr(v)),
        HExpr::Load { addr, size, signed } => {
            let ty = if *signed { c_type(*size) } else { c_utype(*size) };
            format!("*({ty}*)({})", fmt_expr(addr))
        }
        HExpr::Index(base, idx) => format!("{}[{}]", fmt_expr(base), fmt_expr(idx)),
        HExpr::Deref(base) => format!("*{}", fmt_expr(base)),
    }
}

fn c_utype(size: u8) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        _ => "uint64_t",
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    use BinOp::*;
    match op {
        Add => "+", Sub => "-", And => "&", Or => "|", Xor => "^",
        Shl => "<<", Shr => ">>", Sar => ">>",
        SltS | SltU => "<",
        Mul => "*", MulHS | MulHU | MulHSU => "*hi",
        DivS | DivU => "/", RemS | RemU => "%",
    }
}

fn cmp_sym(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==", CmpOp::Ne => "!=",
        CmpOp::LtS | CmpOp::LtU => "<",
        CmpOp::GeS | CmpOp::GeU => ">=",
    }
}
