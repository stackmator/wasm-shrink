use anyhow::{Context, Result};
use std::io::Write;

pub fn validate_wasm(bytes: &[u8]) -> Result<(), String> {
    // Permissive feature set: our inputs come from real toolchains (e.g. .NET
    // NativeAOT still emits the legacy exception-handling instructions).
    let features = wasmparser::WasmFeatures::default() | wasmparser::WasmFeatures::LEGACY_EXCEPTIONS;
    wasmparser::Validator::new_with_features(features)
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn gzip_len(bytes: &[u8]) -> Result<usize> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).context("gzip encode")?;
    Ok(enc.finish()?.len())
}

pub fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let v = n as f64;
    if v >= GB {
        format!("{:.2} GB", v / GB)
    } else if v >= MB {
        format!("{:.2} MB", v / MB)
    } else if v >= KB {
        format!("{:.1} KB", v / KB)
    } else {
        format!("{n} B")
    }
}

pub fn fmt_delta(delta: i64) -> String {
    let sign = if delta <= 0 { "-" } else { "+" };
    format!("{sign}{}", fmt_bytes(delta.unsigned_abs()))
}

pub fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

pub fn fmt_pct(before: u64, after: u64) -> String {
    if before == 0 {
        return "0.0%".to_string();
    }
    let pct = (after as f64 - before as f64) / before as f64 * 100.0;
    format!("{pct:+.1}%")
}

pub fn read_wasm(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}
