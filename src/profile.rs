use std::collections::HashSet;
use wasmparser::{Encoding, Payload, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    DotnetMono,
    DotnetAot,
    Dotnet,
    Emscripten,
    Rust,
    Go,
    Wasi,
    Unknown,
}

impl Runtime {
    pub fn label(self) -> &'static str {
        match self {
            Runtime::DotnetMono => "dotnet (Mono interpreter)",
            Runtime::DotnetAot => "dotnet (AOT-compiled)",
            Runtime::Dotnet => "dotnet",
            Runtime::Emscripten => "emscripten",
            Runtime::Rust => "rust",
            Runtime::Go => "go",
            Runtime::Wasi => "wasi",
            Runtime::Unknown => "unknown",
        }
    }

    pub fn is_dotnet(self) -> bool {
        matches!(self, Runtime::DotnetMono | Runtime::DotnetAot | Runtime::Dotnet)
    }

    /// Custom sections that must never be stripped for this runtime.
    pub fn profile_keep(self) -> HashSet<String> {
        let mut keep = HashSet::new();
        if self.is_dotnet() {
            // Read by the .NET JS host loader at startup.
            keep.insert("dotnet".to_string());
        }
        keep
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub runtime: Runtime,
    pub evidence: Vec<String>,
}

impl Detection {
    pub fn summary(&self) -> String {
        if self.evidence.is_empty() {
            self.runtime.label().to_string()
        } else {
            format!("{} — {}", self.runtime.label(), self.evidence.join(", "))
        }
    }
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Heuristic runtime detection from imports, exports, and custom section payloads.
pub fn detect(bytes: &[u8]) -> Detection {
    let mut evidence: Vec<String> = Vec::new();
    let mut mono = false;
    let mut interp = false;
    let mut aot = false;
    let mut dotnet_sec = false;
    let mut emscripten = false;
    let mut rustc = false;
    let mut go = false;
    let mut wasi = false;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => break,
        };
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding == Encoding::Component {
                    return Detection {
                        runtime: Runtime::Unknown,
                        evidence: vec!["component module".into()],
                    };
                }
            }
            Payload::ImportSection(reader) => {
                for imp in reader.into_imports().flatten() {
                    let field = imp.name.as_bytes();
                    let module = imp.module;
                    if field.starts_with(b"mono_interp") {
                        interp = true;
                        mono = true;
                    } else if field.starts_with(b"mono_") {
                        mono = true;
                    }
                    if contains_bytes(field, b"emscripten")
                        || contains_bytes(module.as_bytes(), b"emscripten")
                    {
                        emscripten = true;
                    }
                    if module == "wasi_snapshot_preview1" {
                        wasi = true;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for e in reader.into_iter().flatten() {
                    // NativeAOT-compiled .NET modules export one
                    // `mono_aot_<Assembly>_get_method` per AOT image; the
                    // interpreted Mono runtime does not.
                    if e.name.as_bytes().starts_with(b"mono_aot_") {
                        aot = true;
                    }
                }
            }
            Payload::CustomSection(c) => {
                let name = c.name();
                if name == "dotnet" {
                    if !dotnet_sec {
                        evidence.push("custom section \"dotnet\"".into());
                    }
                    dotnet_sec = true;
                }
                // Scan payloads for toolchain markers (producers etc.).
                let data = c.data();
                let scan = &data[..data.len().min(1 << 20)];
                if !rustc && contains_bytes(scan, b"rustc") {
                    rustc = true;
                    evidence.push("producers: rustc".into());
                }
                if !go && (contains_bytes(scan, b"go1.") || contains_bytes(scan, b"Go lift")) {
                    go = true;
                    evidence.push("producers: go".into());
                }
                if !emscripten && contains_bytes(scan, b"emscripten") {
                    emscripten = true;
                    evidence.push("producers: emscripten".into());
                }
            }
            _ => {}
        }
    }

    if aot {
        evidence.push("exports: mono_aot_*".into());
    }
    if mono {
        evidence.push("imports: mono_*".into());
    }
    if interp && !aot {
        evidence.push("imports: mono_interp_*".into());
    }
    if wasi && !mono && !emscripten {
        evidence.push("imports: wasi_snapshot_preview1".into());
    }

    // AOT-compiled output links the interpreter runtime too, so the
    // `mono_aot_*` exports take precedence over `mono_interp_*` imports.
    let runtime = if aot {
        Runtime::DotnetAot
    } else if interp {
        Runtime::DotnetMono
    } else if mono || dotnet_sec {
        Runtime::Dotnet
    } else if rustc {
        Runtime::Rust
    } else if go {
        Runtime::Go
    } else if emscripten {
        Runtime::Emscripten
    } else if wasi {
        Runtime::Wasi
    } else {
        Runtime::Unknown
    };

    Detection { runtime, evidence }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{
        EntityType, ExportKind, ExportSection, FunctionSection, ImportSection, Module, TypeSection,
    };

    /// Build a module with one imported function and one exported function.
    fn module_with(import_name: &str, export_name: &str) -> Vec<u8> {
        let mut m = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([], []);
        m.section(&types);
        let mut imports = ImportSection::new();
        imports.import("env", import_name, EntityType::Function(0));
        m.section(&imports);
        let mut funcs = FunctionSection::new();
        funcs.function(0);
        m.section(&funcs);
        let mut exports = ExportSection::new();
        exports.export(export_name, ExportKind::Func, 0);
        m.section(&exports);
        let mut code = wasm_encoder::CodeSection::new();
        let mut f = wasm_encoder::Function::new([]);
        f.instruction(&wasm_encoder::Instruction::End);
        code.function(&f);
        m.section(&code);
        m.finish()
    }

    #[test]
    fn detects_nativeaot_by_mono_aot_export() {
        let bytes = module_with("mono_wasm_init", "mono_aot_corlib_get_method");
        let det = detect(&bytes);
        assert_eq!(det.runtime, Runtime::DotnetAot, "evidence: {:?}", det.evidence);
    }

    #[test]
    fn detects_mono_by_interp_import() {
        let bytes = module_with("mono_interp_entry", "foobar");
        let det = detect(&bytes);
        assert_eq!(det.runtime, Runtime::DotnetMono, "evidence: {:?}", det.evidence);
    }

    #[test]
    fn detects_generic_dotnet_without_aot_or_interp() {
        let bytes = module_with("mono_wasm_init", "foobar");
        let det = detect(&bytes);
        assert_eq!(det.runtime, Runtime::Dotnet, "evidence: {:?}", det.evidence);
    }

    #[test]
    fn detects_unknown_for_empty_module() {
        let det = detect(&Module::new().finish());
        assert_eq!(det.runtime, Runtime::Unknown);
    }
}
