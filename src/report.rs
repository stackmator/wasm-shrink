use crate::analysis::Analysis;
use crate::passes::{kind_equiv, Check, PipelineResult};
use crate::profile::Detection;
use crate::wasm_util::{fmt_bytes, fmt_count, fmt_delta, fmt_pct};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RULE: &str = "────────────────────────";

fn header() {
    println!("WASM-TRIM {VERSION}");
}

fn input_block(path: &std::path::Path, a: &Analysis, det: &Detection, gzip: usize) {
    println!("\nInput\n{RULE}");
    println!("  File              {}", path.display());
    println!("  Size              {}", fmt_bytes(a.module_bytes));
    println!("  Compressed (gzip) {}", fmt_bytes(gzip as u64));
    println!(
        "  Functions         {} ({} imported, {} defined)",
        fmt_count(a.n_functions()),
        fmt_count(a.n_func_imports as usize),
        fmt_count(a.n_defined())
    );
    println!("  Data              {}", fmt_bytes(a.total_data_bytes));
    println!("  Runtime           {}", det.summary());
}

pub fn print_analyze(path: &std::path::Path, a: &Analysis, det: &Detection, gzip: usize) {
    header();
    input_block(path, a, det, gzip);

    println!("\nAnalysis\n{RULE}");
    println!(
        "  Unreachable functions   {}",
        fmt_count(a.unreachable_count)
    );
    println!("  Duplicate functions     {}", fmt_count(a.dup_count));
    println!("  Unused data segments    {}", fmt_count(a.unused_data_count()));
    println!(
        "  Duplicate data segments {}",
        fmt_count(a.duplicate_active_data_count())
    );
    println!(
        "  Custom sections         {} ({})",
        fmt_count(a.custom_sections().count()),
        fmt_bytes(a.custom_bytes)
    );
    println!("  Entry points (roots)    {}", fmt_count(a.roots_count));
    println!(
        "  Code / data             {} / {}",
        fmt_bytes(a.total_code_bytes),
        fmt_bytes(a.total_data_bytes)
    );

    println!("\nSections\n{RULE}");
    for s in &a.sections {
        match &s.custom_name {
            Some(name) => println!(
                "  {:>2} {:<16} {}  (custom: {})",
                s.id,
                "custom",
                fmt_bytes(s.size),
                name
            ),
            None => println!("  {:>2} {:<16} {}", s.id, s.name(), fmt_bytes(s.size)),
        }
    }

    println!("\nNext steps\n{RULE}");
    println!("  wasm-trim optimize {} -o <output>", path.display());
    println!("  wasm-trim diff {} <optimized>", path.display());
}

pub fn print_optimize(
    path: &std::path::Path,
    res: &PipelineResult,
    det: &Detection,
    gzip_before: usize,
    gzip_after: usize,
    out_path: &std::path::Path,
) {
    header();
    input_block(path, &res.orig, det, gzip_before);

    println!("\nAnalysis\n{RULE}");
    println!(
        "  Unreachable functions     {}",
        fmt_count(res.orig.unreachable_count)
    );
    println!(
        "  Duplicate functions       {}",
        fmt_count(res.orig.dup_count)
    );
    println!(
        "  Unused data segments      {}",
        fmt_count(res.orig.unused_data_count())
    );
    println!(
        "  Duplicate data segments   {}",
        fmt_count(res.orig.duplicate_active_data_count())
    );
    if res.stripped_customs.is_empty() {
        println!("  Debug/custom sections     none strippable");
    } else {
        let total: u64 = res.stripped_customs.iter().map(|(_, s)| *s).sum();
        let names: Vec<&str> = res.stripped_customs.iter().map(|(n, _)| n.as_str()).collect();
        println!(
            "  Debug/custom sections     {} ({})",
            fmt_bytes(total),
            names.join(", ")
        );
    }

    if res.stages.is_empty() {
        println!("\nOptimization\n{RULE}");
        println!("  (all passes disabled — output unchanged)");
    } else {
        println!("\nOptimization\n{RULE}");
        for st in &res.stages {
            let mut extra = Vec::new();
            if st.funcs_removed > 0 {
                extra.push(format!("{} funcs", fmt_count(st.funcs_removed)));
            }
            if st.data_removed > 0 {
                extra.push(format!("{} data", fmt_count(st.data_removed)));
            }
            if st.custom_removed > 0 {
                extra.push(format!(
                    "{} custom ({})",
                    fmt_count(st.custom_removed),
                    fmt_bytes(st.custom_bytes_removed)
                ));
            }
            let suffix = if extra.is_empty() {
                String::new()
            } else {
                format!("  ({})", extra.join(", "))
            };
            println!(
                "  {:<24} {}{suffix}",
                st.label,
                fmt_delta(st.delta())
            );
        }
    }

    let before = res.orig.module_bytes;
    let after = res.final_analysis.module_bytes;
    println!("\nResult\n{RULE}");
    println!(
        "  {} -> {}",
        fmt_bytes(before),
        fmt_bytes(after)
    );
    println!(
        "  {} -> {}",
        fmt_bytes(gzip_before as u64),
        fmt_bytes(gzip_after as u64)
    );
    println!();
    println!("  Raw:  {}", fmt_pct(before, after));
    println!(
        "  Gzip: {}",
        fmt_pct(gzip_before as u64, gzip_after as u64)
    );

    println!("\nBehavior-preserving checks\n{RULE}");
    for c in &res.checks {
        print_check(c);
    }

    for w in &res.warnings {
        println!("\n  ! {w}");
    }

    println!("\nWrote {}", out_path.display());
}

pub fn print_check(c: &Check) {
    let mark = if c.ok { "✓" } else { "✗" };
    println!("  {} {:<28} {}", mark, c.label, c.detail);
}

pub fn diff_issues(a: &Analysis, b: &Analysis) -> Vec<String> {
    let mut issues = Vec::new();

    if a.imports != b.imports {
        if a.imports.len() != b.imports.len() {
            issues.push(format!(
                "imports differ: {} vs {} entries",
                a.imports.len(),
                b.imports.len()
            ));
        } else {
            for (i, (x, y)) in a.imports.iter().zip(b.imports.iter()).enumerate() {
                if x != y {
                    issues.push(format!(
                        "import #{i} differs: {}.{} vs {}.{}",
                        x.module, x.name, y.module, y.name
                    ));
                    break;
                }
            }
        }
    }

    let mut ea: Vec<(String, u8)> = a
        .exports
        .iter()
        .map(|e| (e.name.clone(), kind_equiv(e.kind)))
        .collect();
    let mut eb: Vec<(String, u8)> = b
        .exports
        .iter()
        .map(|e| (e.name.clone(), kind_equiv(e.kind)))
        .collect();
    ea.sort();
    eb.sort();
    if ea != eb {
        let only_a: Vec<&str> = ea
            .iter()
            .filter(|e| !eb.contains(e))
            .map(|(n, _)| n.as_str())
            .collect();
        let only_b: Vec<&str> = eb
            .iter()
            .filter(|e| !ea.contains(e))
            .map(|(n, _)| n.as_str())
            .collect();
        let mut parts = Vec::new();
        if !only_a.is_empty() {
            parts.push(format!("only in A: {}", only_a.join(", ")));
        }
        if !only_b.is_empty() {
            parts.push(format!("only in B: {}", only_b.join(", ")));
        }
        if parts.is_empty() {
            parts.push("export kinds differ".into());
        }
        issues.push(format!("exports differ: {}", parts.join("; ")));
    }

    if a.start.is_some() != b.start.is_some() {
        issues.push("start section presence differs".into());
    }

    issues
}

#[allow(clippy::too_many_arguments)]
pub fn print_diff(
    path_a: &std::path::Path,
    a: &Analysis,
    gzip_a: usize,
    det_a: &Detection,
    path_b: &std::path::Path,
    b: &Analysis,
    gzip_b: usize,
    det_b: &Detection,
) {
    header();
    println!("\nA: {}\n{RULE}", path_a.display());
    println!("  Size              {}", fmt_bytes(a.module_bytes));
    println!("  Compressed (gzip) {}", fmt_bytes(gzip_a as u64));
    println!(
        "  Functions         {} ({} defined)",
        fmt_count(a.n_functions()),
        fmt_count(a.n_defined())
    );
    println!("  Data              {}", fmt_bytes(a.total_data_bytes));
    println!("  Runtime           {}", det_a.summary());

    println!("\nB: {}\n{RULE}", path_b.display());
    println!("  Size              {}", fmt_bytes(b.module_bytes));
    println!("  Compressed (gzip) {}", fmt_bytes(gzip_b as u64));
    println!(
        "  Functions         {} ({} defined)",
        fmt_count(b.n_functions()),
        fmt_count(b.n_defined())
    );
    println!("  Data              {}", fmt_bytes(b.total_data_bytes));
    println!("  Runtime           {}", det_b.summary());

    println!("\nDelta\n{RULE}");
    println!(
        "  Raw:  {} -> {}  ({})",
        fmt_bytes(a.module_bytes),
        fmt_bytes(b.module_bytes),
        fmt_pct(a.module_bytes, b.module_bytes)
    );
    println!(
        "  Gzip: {} -> {}  ({})",
        fmt_bytes(gzip_a as u64),
        fmt_bytes(gzip_b as u64),
        fmt_pct(gzip_a as u64, gzip_b as u64)
    );

    println!("\nInterface\n{RULE}");
    let issues = diff_issues(a, b);
    if issues.is_empty() {
        println!("  ✓ imports      {} preserved", fmt_count(a.imports.len()));
        println!("  ✓ exports      {} preserved", fmt_count(a.exports.len()));
        println!(
            "  ✓ start        {}",
            if a.start.is_some() {
                "present in both"
            } else {
                "absent in both"
            }
        );
    } else {
        for i in &issues {
            println!("  ✗ {i}");
        }
    }

    println!("\nSections\n{RULE}");
    println!("  {:<16} {:>12} {:>12}", "section", "A", "B");
    let max_id = a
        .sections
        .iter()
        .chain(b.sections.iter())
        .map(|s| s.id)
        .max()
        .unwrap_or(0);
    for id in 0..=max_id {
        let sa: u64 = a.sections.iter().filter(|s| s.id == id).map(|s| s.size).sum();
        let sb: u64 = b.sections.iter().filter(|s| s.id == id).map(|s| s.size).sum();
        if sa == 0 && sb == 0 {
            continue;
        }
        let name = crate::analysis::section_name(id);
        println!(
            "  {:<16} {:>12} {:>12}",
            name,
            fmt_bytes(sa),
            fmt_bytes(sb)
        );
    }
    let ca: u64 = a.custom_bytes;
    let cb: u64 = b.custom_bytes;
    println!(
        "  {:<16} {:>12} {:>12}",
        "custom",
        fmt_bytes(ca),
        fmt_bytes(cb)
    );
}
