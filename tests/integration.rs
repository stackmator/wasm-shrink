use std::borrow::Cow;
use std::path::Path;

use wasm_encoder::{
    CodeSection, ConstExpr, CustomSection, DataCountSection, DataSection, EntityType,
    ElementSection, Elements, ExportKind, ExportSection, Function, FunctionSection,
    GlobalSection, GlobalType, ImportSection, Instruction, MemorySection, MemoryType, Module,
    RefType, StartSection, TableSection, TableType, TypeSection, ValType,
};
use wasm_trim::passes::{optimize, PassConfig};
use wasm_trim::wasm_util::{read_wasm, validate_wasm};

/// Synthetic module covering every MVP pass:
/// - import env.log
/// - exported run + helper, memory export
/// - helper/dupA/dupB byte-identical (folding candidates)
/// - elemOnly reachable only via active element segment
/// - globalRoot reachable only via funcref global init
/// - dead1 -> dead2 unreachable chain
/// - startFn as start section
/// - data: active duplicate, active distinct, referenced passive, unused passive
/// - custom: name, producers, sourceMappingURL (stripped),
///   target_features, dotnet, mydata (kept)
fn build_synthetic() -> Vec<u8> {
    let mut m = Module::new();

    let mut types = TypeSection::new();
    types.ty().function([], []); // type 0: () -> ()
    m.section(&types);

    let mut imports = ImportSection::new();
    imports.import("env", "log", EntityType::Function(0)); // func 0
    m.section(&imports);

    // defined: 1 run, 2 helper, 3 dupA, 4 dupB, 5 elemOnly,
    //          6 globalRoot, 7 dead1, 8 dead2, 9 startFn
    let mut functions = FunctionSection::new();
    for _ in 0..9 {
        functions.function(0);
    }
    m.section(&functions);

    let mut tables = TableSection::new();
    tables.table(TableType {
        element_type: RefType::FUNCREF,
        table64: false,
        minimum: 4,
        maximum: None,
        shared: false,
    });
    m.section(&tables);

    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    m.section(&memories);

    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::Ref(RefType::FUNCREF),
            mutable: false,
            shared: false,
        },
        &ConstExpr::ref_func(6),
    );
    m.section(&globals);

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 1);
    exports.export("helper", ExportKind::Func, 2);
    exports.export("memory", ExportKind::Memory, 0);
    m.section(&exports);

    m.section(&StartSection { function_index: 9 });

    let mut elems = ElementSection::new();
    elems.active(None, &ConstExpr::i32_const(0), Elements::Functions(Cow::Borrowed(&[5])));
    m.section(&elems);

    m.section(&DataCountSection { count: 5 });

    let mut code = CodeSection::new();
    // run: call helper; call dupB; memory.init data3
    let mut run = Function::new([]);
    run.instruction(&Instruction::Call(2));
    run.instruction(&Instruction::Call(4));
    run.instruction(&Instruction::I32Const(0));
    run.instruction(&Instruction::I32Const(0));
    run.instruction(&Instruction::I32Const(5));
    run.instruction(&Instruction::MemoryInit { mem: 0, data_index: 3 });
    run.instruction(&Instruction::End);
    code.function(&run);

    let fold_body = |code: &mut CodeSection| {
        let mut f = Function::new([]);
        f.instruction(&Instruction::I32Const(1));
        f.instruction(&Instruction::I32Const(2));
        f.instruction(&Instruction::I32Add);
        f.instruction(&Instruction::Drop);
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    fold_body(&mut code); // helper
    fold_body(&mut code); // dupA
    fold_body(&mut code); // dupB

    let simple = |code: &mut CodeSection, instrs: &[Instruction]| {
        let mut f = Function::new([]);
        for i in instrs {
            f.instruction(i);
        }
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    simple(&mut code, &[Instruction::Nop]); // elemOnly
    simple(
        &mut code,
        &[Instruction::I32Const(7), Instruction::Drop],
    ); // globalRoot
    simple(&mut code, &[Instruction::Call(8)]); // dead1
    simple(
        &mut code,
        &[Instruction::I32Const(6), Instruction::Drop],
    ); // dead2
    simple(
        &mut code,
        &[Instruction::I32Const(8), Instruction::Drop],
    ); // startFn
    m.section(&code);

    let mut data = DataSection::new();
    data.active(0, &ConstExpr::i32_const(0), b"hello".iter().copied()); // 0
    data.active(0, &ConstExpr::i32_const(0), b"hello".iter().copied()); // 1: duplicate of 0
    data.active(0, &ConstExpr::i32_const(6), b"world".iter().copied()); // 2
    data.passive(b"used-bytes!!".iter().copied()); // 3: referenced by run
    data.passive(b"never-referenced-xyz".iter().copied()); // 4: unused
    m.section(&data);

    let customs: [(&str, &[u8]); 6] = [
        ("name", b""),
        ("producers", b"whatever-producers"),
        ("sourceMappingURL", b"x.wasm.map"),
        ("target_features", b"+atomics"),
        ("dotnet", b"dotnet-profile-marker"),
        ("mydata", b"keep-me"),
    ];
    for (name, payload) in customs {
        m.section(&CustomSection {
            name: Cow::Borrowed(name),
            data: Cow::Borrowed(payload),
        });
    }

    m.finish()
}

fn all_passes() -> PassConfig {
    PassConfig::default()
}

#[test]
fn synthetic_optimize_is_behavior_preserving() {
    let input = build_synthetic();
    validate_wasm(&input).expect("synthetic input must validate");

    let res = optimize(&input, &all_passes()).expect("optimize");

    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    assert!(res.deterministic, "output must be deterministic");
    validate_wasm(&res.output).expect("output must validate");

    let a = &res.final_analysis;
    assert_eq!(a.n_func_imports, 1, "import preserved");
    assert_eq!(a.imports[0].module, "env");
    assert_eq!(a.imports[0].name, "log");

// Peephole collapses helper/dupA/dupB/elemOnly/globalRoot/dead2/startFn
// to bare `end`, so folding merges them; only `run` plus the shared `end`
// body remain after DCE.
    assert_eq!(a.n_defined(), 2, "expected 2 defined functions");

    let export_names: Vec<&str> = a.exports.iter().map(|e| e.name.as_str()).collect();
    assert!(export_names.contains(&"run"));
    assert!(export_names.contains(&"helper"));
    assert!(export_names.contains(&"memory"));
    assert_eq!(export_names.len(), 3);

    assert!(a.start.is_some(), "start section must survive");

    // 5 data segments - 1 active duplicate - 1 unused passive = 3
    assert_eq!(a.data.len(), 3, "expected 3 data segments");

    let custom_names: Vec<&str> = a
        .custom_sections()
        .filter_map(|s| s.custom_name.as_deref())
        .collect();
    for gone in ["name", "producers", "sourceMappingURL"] {
        assert!(!custom_names.contains(&gone), "'{gone}' should be stripped");
    }
    for kept in ["target_features", "dotnet", "mydata"] {
        assert!(custom_names.contains(&kept), "'{kept}' should be kept");
    }

    assert!(
        res.output.len() < input.len(),
        "output ({}) should be smaller than input ({})",
        res.output.len(),
        input.len()
    );

    assert_eq!(res.stages.len(), 6, "all six stages should run");
}

#[test]
fn passes_disabled_is_identity() {
    let input = build_synthetic();
    let cfg = PassConfig {
        strip: false,
        data: false,
        dedupe: false,
        dce: false,
        code: false,
        merge: false,
        ..PassConfig::default()
    };
    let res = optimize(&input, &cfg).expect("optimize");
    assert!(res.stages.is_empty());
    assert!(res.checks.iter().all(|c| c.ok));
    assert_eq!(res.output, input, "no passes => byte-identical output");
}

#[test]
fn does_not_overwrite_input_via_cli() {
    let input = build_synthetic();
    let dir = std::env::temp_dir().join(format!("wasm-trim-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("in.wasm");
    std::fs::write(&input_path, &input).unwrap();

    let bin = env!("CARGO_BIN_EXE_wasm-trim");
    let out = std::process::Command::new(bin)
        .args(["optimize"])
        .arg(&input_path)
        .arg("-o")
        .arg(&input_path)
        .output()
        .expect("run wasm-trim");
    assert!(!out.status.success(), "refusing same input/output must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}");

    // different -o works
    let out_path = dir.join("out.wasm");
    let out = std::process::Command::new(bin)
        .args(["optimize"])
        .arg(&input_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run wasm-trim");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out_path.exists());
    // input untouched
    assert_eq!(std::fs::read(&input_path).unwrap(), input);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn optimize_dotnet_aot_fixture() {
    let path = Path::new("testdata/fixtures/dotnet.native.aot.wasm");
    if !path.exists() {
        eprintln!("fixture missing, skipping");
        return;
    }
    let input = read_wasm(path).unwrap();
    let res = optimize(&input, &all_passes()).expect("optimize aot fixture");

    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    assert!(res.deterministic);
    validate_wasm(&res.output).expect("output validates");
    assert!(
        res.output.len() < input.len(),
        "expected size reduction: {} -> {}",
        input.len(),
        res.output.len()
    );
    // interface preserved
    assert_eq!(res.orig.imports.len(), res.final_analysis.imports.len());
    assert_eq!(res.orig.exports.len(), res.final_analysis.exports.len());
}

#[test]
#[ignore = "large 19 MB fixture; run with --ignored after publishing a large Blazor WASM app with RunAOTCompilation"]
fn optimize_large_aot_fixture() {
    // Not produced by build-fixtures.ps1. To create it, publish a large
    // standalone Blazor WASM app with -p:RunAOTCompilation=true and copy its
    // wwwroot/_framework/dotnet.native.*.wasm here.
    let path = Path::new("testdata/fixtures/dotnet.native.large.aot.wasm");
    if !path.exists() {
        eprintln!("large fixture missing, skipping");
        return;
    }
    let input = read_wasm(path).unwrap();
    let res = optimize(&input, &all_passes()).expect("optimize large aot fixture");

    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    assert!(res.deterministic);
    validate_wasm(&res.output).expect("output validates");
    assert!(
        res.output.len() < input.len(),
        "expected size reduction: {} -> {}",
        input.len(),
        res.output.len()
    );
    assert_eq!(res.orig.imports.len(), res.final_analysis.imports.len());
    assert_eq!(res.orig.exports.len(), res.final_analysis.exports.len());
}

#[test]
fn optimize_dotnet_mono_fixture() {
    let path = Path::new("testdata/fixtures/dotnet.native.wasm");
    if !path.exists() {
        eprintln!("fixture missing, skipping");
        return;
    }
    let input = read_wasm(path).unwrap();
    let res = optimize(&input, &all_passes()).expect("optimize mono fixture");

    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    assert!(res.deterministic);
    validate_wasm(&res.output).expect("output validates");
    assert_eq!(res.orig.imports.len(), res.final_analysis.imports.len());
    assert_eq!(res.orig.exports.len(), res.final_analysis.exports.len());
}

/// Functions that are instruction-identical except for constant immediates,
/// used to exercise the function-merging pass (constant parameterization,
/// local-index shifting, wrapper generation).
fn build_const_variants() -> Vec<u8> {
    let mut m = Module::new();

    let mut types = TypeSection::new();
    types.ty().function([], [ValType::I32]); // type 0
    types.ty().function([ValType::I32, ValType::I32], [ValType::I32]); // type 1
    m.section(&types);

    // 0 h5, 1 h7, 2 h9, 3 pA, 4 pB, 5 lA, 6 lB, 7 run
    let mut funcs = FunctionSection::new();
    for t in [0u32, 0, 0, 1, 1, 1, 1, 0] {
        funcs.function(t);
    }
    m.section(&funcs);

    let mut exports = ExportSection::new();
    for (i, name) in ["h5", "h7", "h9", "pA", "pB", "lA", "lB", "run"]
        .iter()
        .enumerate()
    {
        exports.export(name, ExportKind::Func, i as u32);
    }
    m.section(&exports);

    let mut code = CodeSection::new();

    let h = |code: &mut CodeSection, k: i32| {
        let mut f = Function::new([]);
        f.instruction(&Instruction::I32Const(0));
        for _ in 0..15 {
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Add);
        }
        f.instruction(&Instruction::I32Const(k));
        f.instruction(&Instruction::I32Add);
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    h(&mut code, 5);
    h(&mut code, 7);
    h(&mut code, 9);

    let p = |code: &mut CodeSection, k: i32| {
        let mut f = Function::new([]);
        f.instruction(&Instruction::LocalGet(0));
        f.instruction(&Instruction::LocalGet(1));
        f.instruction(&Instruction::I32Add);
        for _ in 0..20 {
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Add);
        }
        f.instruction(&Instruction::I32Const(k));
        f.instruction(&Instruction::I32Add);
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    p(&mut code, 100);
    p(&mut code, 200);

    let l = |code: &mut CodeSection, k: i32| {
        let mut f = Function::new([(1, ValType::I32)]);
        f.instruction(&Instruction::LocalGet(0));
        f.instruction(&Instruction::LocalSet(2));
        f.instruction(&Instruction::LocalGet(2));
        f.instruction(&Instruction::LocalGet(1));
        f.instruction(&Instruction::I32Add);
        for _ in 0..20 {
            f.instruction(&Instruction::I32Const(2));
            f.instruction(&Instruction::I32Mul);
        }
        f.instruction(&Instruction::I32Const(k));
        f.instruction(&Instruction::I32Add);
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    l(&mut code, 11);
    l(&mut code, 22);

    let mut run = Function::new([]);
    run.instruction(&Instruction::Call(0));
    run.instruction(&Instruction::Call(1));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::Call(2));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::I32Const(1));
    run.instruction(&Instruction::I32Const(2));
    run.instruction(&Instruction::Call(3));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::I32Const(3));
    run.instruction(&Instruction::I32Const(4));
    run.instruction(&Instruction::Call(4));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::I32Const(5));
    run.instruction(&Instruction::I32Const(6));
    run.instruction(&Instruction::Call(5));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::I32Const(7));
    run.instruction(&Instruction::I32Const(8));
    run.instruction(&Instruction::Call(6));
    run.instruction(&Instruction::I32Add);
    run.instruction(&Instruction::End);
    code.function(&run);

    m.section(&code);
    m.finish()
}

/// Variants that are structurally identical except for a callee and one
/// constant, exercising call-target merging with argument spilling and
/// multi-target selector dispatch.
fn build_call_variants() -> Vec<u8> {
    let mut m = Module::new();

    let mut types = TypeSection::new();
    types
        .ty()
        .function([ValType::I32, ValType::I32], [ValType::I32]);
    m.section(&types);

    // 0 hAdd, 1 hMul, 2 hSub, 3 v1, 4 v2, 5 v3, 6 v4, 7 driver
    let mut funcs = FunctionSection::new();
    for _ in 0..8 {
        funcs.function(0);
    }
    m.section(&funcs);

    let mut exports = ExportSection::new();
    for (i, name) in ["hAdd", "hMul", "hSub", "v1", "v2", "v3", "v4", "driver"]
        .iter()
        .enumerate()
    {
        exports.export(name, ExportKind::Func, i as u32);
    }
    m.section(&exports);

    let mut code = CodeSection::new();
    let helper = |code: &mut CodeSection, op: Instruction| {
        let mut f = Function::new([]);
        f.instruction(&Instruction::LocalGet(0));
        f.instruction(&Instruction::LocalGet(1));
        f.instruction(&op);
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    helper(&mut code, Instruction::I32Add);
    helper(&mut code, Instruction::I32Mul);
    helper(&mut code, Instruction::I32Sub);

    let variant = |code: &mut CodeSection, target: u32, first_const: i32| {
        let mut f = Function::new([]);
        f.instruction(&Instruction::LocalGet(0));
        f.instruction(&Instruction::LocalGet(1));
        f.instruction(&Instruction::Call(target));
        for k in 0..20 {
            let c = if k == 0 { first_const } else { 1 };
            f.instruction(&Instruction::I32Const(c));
            f.instruction(&Instruction::I32Add);
        }
        f.instruction(&Instruction::End);
        code.function(&f);
    };
    variant(&mut code, 0, 1);
    variant(&mut code, 1, 1);
    variant(&mut code, 2, 1);
    variant(&mut code, 1, 2);

    let mut d = Function::new([]);
    for (k, t) in [3u32, 4, 5, 6].iter().enumerate() {
        d.instruction(&Instruction::LocalGet(0));
        d.instruction(&Instruction::LocalGet(1));
        d.instruction(&Instruction::Call(*t));
        if k > 0 {
            d.instruction(&Instruction::I32Add);
        }
    }
    d.instruction(&Instruction::End);
    code.function(&d);

    m.section(&code);
    m.finish()
}

#[test]
fn merge_call_targets_preserves_behavior_via_node() {
    if std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("node not available, skipping");
        return;
    }

    let input = build_call_variants();
    validate_wasm(&input).expect("synthetic input must validate");

    let cfg = PassConfig {
        strip: false,
        data: false,
        dedupe: false,
        dce: false,
        code: false,
        ..PassConfig::default()
    };
    let res = optimize(&input, &cfg).expect("optimize");
    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    validate_wasm(&res.output).expect("output must validate");
    assert!(res.deterministic);
    assert!(
        res.final_analysis.n_functions() > res.orig.n_functions(),
        "call-target merging should append functions"
    );

    let dir = std::env::temp_dir().join(format!("wasm-trim-callmerge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.wasm");
    let b = dir.join("b.wasm");
    std::fs::write(&a, &input).unwrap();
    std::fs::write(&b, &res.output).unwrap();

    let script = r#"
const fs = require('fs');
const load = p => new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(p)), {}).exports;
const A = load(process.argv[1]), B = load(process.argv[2]);
const names = ['hAdd','hMul','hSub','v1','v2','v3','v4','driver'];
let ok = true;
for (const n of names) {
  const x = A[n](3, 4), y = B[n](3, 4);
  if (x !== y) { ok = false; console.error('mismatch', n, x, y); }
}
process.exit(ok ? 0 : 1);
"#;
    let out = std::process::Command::new("node")
        .arg("-e")
        .arg(script)
        .arg(&a)
        .arg(&b)
        .output()
        .expect("run node");
    assert!(
        out.status.success(),
        "node behavior mismatch: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn merge_preserves_behavior_via_node() {
    if std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("node not available, skipping");
        return;
    }

    let input = build_const_variants();
    validate_wasm(&input).expect("synthetic input must validate");

    let cfg = PassConfig {
        strip: false,
        data: false,
        dedupe: false,
        dce: false,
        code: false,
        ..PassConfig::default()
    };
    let res = optimize(&input, &cfg).expect("optimize");
    for c in &res.checks {
        assert!(c.ok, "check '{}' failed: {}", c.label, c.detail);
    }
    validate_wasm(&res.output).expect("output must validate");
    assert!(res.deterministic);
    assert!(
        res.final_analysis.n_functions() > res.orig.n_functions(),
        "merging should append functions"
    );

    let dir = std::env::temp_dir().join(format!("wasm-trim-merge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.wasm");
    let b = dir.join("b.wasm");
    std::fs::write(&a, &input).unwrap();
    std::fs::write(&b, &res.output).unwrap();

    let script = r#"
const fs = require('fs');
const load = p => new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(p)), {}).exports;
const A = load(process.argv[1]), B = load(process.argv[2]);
const calls = [['h5',[]],['h7',[]],['h9',[]],['pA',[1,2]],['pB',[3,4]],['lA',[5,6]],['lB',[7,8]],['run',[]]];
let ok = true;
for (const [n, args] of calls) {
  const x = A[n](...args), y = B[n](...args);
  if (x !== y) { ok = false; console.error('mismatch', n, x, y); }
}
process.exit(ok ? 0 : 1);
"#;
    let out = std::process::Command::new("node")
        .arg("-e")
        .arg(script)
        .arg(&a)
        .arg(&b)
        .output()
        .expect("run node");
    assert!(
        out.status.success(),
        "node behavior mismatch: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&dir).ok();
}

