use crate::analysis::analyze;
use crate::passes::{optimize, PassConfig};
use crate::profile::{self, Runtime};
use crate::report;
use crate::wasm_util::{fmt_bytes, gzip_len, read_wasm, validate_wasm};
use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "wasm-trim", version, about = "Post-link WebAssembly size optimizer")]
pub struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// File to analyze (shorthand for `wasm-trim analyze FILE`)
    file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a module without modifying it
    Analyze {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = ProfileArg::Auto)]
        profile: ProfileArg,
    },
    /// Optimize a module (never modifies the input)
    Optimize {
        input: PathBuf,
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = ProfileArg::Auto)]
        profile: ProfileArg,
        /// Extra custom sections to strip; use `all` for every unprotected section
        #[arg(long = "strip-custom", value_name = "NAME")]
        strip_custom: Vec<String>,
        /// Custom sections that must never be stripped
        #[arg(long = "keep-custom", value_name = "NAME")]
        keep_custom: Vec<String>,
        /// Disable section stripping (name section still stripped when needed)
        #[arg(long)]
        no_strip: bool,
        /// Disable data segment optimization
        #[arg(long)]
        no_data: bool,
        /// Disable duplicate function folding
        #[arg(long)]
        no_dedupe: bool,
        /// Disable dead code elimination
        #[arg(long)]
        no_dce: bool,
        /// Disable instruction-level peephole optimization
        #[arg(long)]
        no_code: bool,
        /// Disable merging of near-duplicate functions
        #[arg(long)]
        no_merge: bool,
    },
    /// Compare two modules (interface, sections, sizes)
    Diff { a: PathBuf, b: PathBuf },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    Auto,
    Dotnet,
    None,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Analyze { input, profile }) => cmd_analyze(&input, profile),
        Some(Cmd::Optimize {
            input,
            output,
            profile,
            strip_custom,
            keep_custom,
            no_strip,
            no_data,
            no_dedupe,
            no_dce,
            no_code,
            no_merge,
        }) => cmd_optimize(
            &input,
            &output,
            profile,
            strip_custom,
            keep_custom,
            !no_strip,
            !no_data,
            !no_dedupe,
            !no_dce,
            !no_code,
            !no_merge,
        ),
        Some(Cmd::Diff { a, b }) => cmd_diff(&a, &b),
        None => {
            if let Some(file) = cli.file {
                cmd_analyze(&file, ProfileArg::Auto)
            } else {
                Cli::command().print_help()?;
                println!();
                Ok(())
            }
        }
    }
}

fn cmd_analyze(input: &std::path::Path, profile_arg: ProfileArg) -> Result<()> {
    let bytes = read_wasm(input)?;
    validate_wasm(&bytes).map_err(|e| anyhow::anyhow!("{}: invalid wasm: {e}", input.display()))?;
    let a = analyze(&bytes)?;
    let det = profile::detect(&bytes);
    let _ = profile_arg;
    let gz = gzip_len(&bytes)?;
    report::print_analyze(input, &a, &det, gz);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_optimize(
    input: &std::path::Path,
    output: &std::path::Path,
    profile_arg: ProfileArg,
    strip_custom: Vec<String>,
    keep_custom: Vec<String>,
    strip: bool,
    data: bool,
    dedupe: bool,
    dce: bool,
    code: bool,
    merge: bool,
) -> Result<()> {
    if output == input {
        bail!("refusing to overwrite the input file; choose a different -o path");
    }
    let bytes = read_wasm(input)?;
    validate_wasm(&bytes).map_err(|e| anyhow::anyhow!("{}: invalid wasm: {e}", input.display()))?;

    let det = profile::detect(&bytes);
    let runtime: Runtime = match profile_arg {
        ProfileArg::Auto => det.runtime,
        ProfileArg::Dotnet => Runtime::Dotnet,
        ProfileArg::None => Runtime::Unknown,
    };
    let profile_keep = match profile_arg {
        ProfileArg::None => Default::default(),
        _ => runtime.profile_keep(),
    };

    let cfg = PassConfig {
        strip,
        data,
        dedupe,
        dce,
        code,
        merge,
        user_strip: strip_custom,
        user_keep: keep_custom,
        profile_keep,
    };

    let gzip_before = gzip_len(&bytes)?;
    let res = optimize(&bytes, &cfg)?;
    let gzip_after = gzip_len(&res.output)?;

    report::print_optimize(input, &res, &det, gzip_before, gzip_after, output);

    let failed: Vec<_> = res.checks.iter().filter(|c| !c.ok).collect();
    if !failed.is_empty() {
        bail!("{} behavior-preserving check(s) failed", failed.len());
    }
    if !res.deterministic {
        bail!("output is not deterministic");
    }

    std::fs::write(output, &res.output)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", output.display()))?;
    Ok(())
}

fn cmd_diff(a_path: &std::path::Path, b_path: &std::path::Path) -> Result<()> {
    let a_bytes = read_wasm(a_path)?;
    let b_bytes = read_wasm(b_path)?;
    validate_wasm(&a_bytes)
        .map_err(|e| anyhow::anyhow!("{}: invalid wasm: {e}", a_path.display()))?;
    validate_wasm(&b_bytes)
        .map_err(|e| anyhow::anyhow!("{}: invalid wasm: {e}", b_path.display()))?;
    let a = analyze(&a_bytes)?;
    let b = analyze(&b_bytes)?;
    let det_a = profile::detect(&a_bytes);
    let det_b = profile::detect(&b_bytes);
    let gz_a = gzip_len(&a_bytes)?;
    let gz_b = gzip_len(&b_bytes)?;
    report::print_diff(a_path, &a, gz_a, &det_a, b_path, &b, gz_b, &det_b);

    let issues = report::diff_issues(&a, &b);
    if !issues.is_empty() {
        bail!("interface differs between the two modules");
    }
    let _ = fmt_bytes(a.module_bytes);
    Ok(())
}
