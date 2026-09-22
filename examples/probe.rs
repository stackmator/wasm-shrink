use std::collections::HashMap;
use wasmparser::{Operator, Parser, Payload};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        "testdata/fixtures/dotnet.native.wasm",
        "testdata/fixtures/dotnet.native.aot.wasm",
    ] {
        let bytes = std::fs::read(path)?;
        println!("\n=== {path} ===");

        // Exact const+binop patterns (adjacent ops)
        let mut patterns: HashMap<String, u64> = HashMap::new();
        let mut i32const_then: HashMap<&'static str, u64> = HashMap::new();
        let mut total = 0u64;
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload? {
                let ops = body.get_operators_reader()?;
                let v: Vec<Operator> = ops.into_iter().collect::<Result<_, _>>()?;
                for w in v.windows(2) {
                    total += 1;
                    let name = match (&w[0], &w[1]) {
                        (Operator::I32Const { .. }, Operator::I32Add) => Some("i32.const+add"),
                        (Operator::I32Const { .. }, Operator::I32Mul) => Some("i32.const+mul"),
                        (Operator::I32Const { .. }, Operator::I32And) => Some("i32.const+and"),
                        (Operator::I32Const { .. }, Operator::I32Or) => Some("i32.const+or"),
                        (Operator::I32Const { .. }, Operator::I32Xor) => Some("i32.const+xor"),
                        (Operator::I32Const { .. }, Operator::I32Sub) => Some("i32.const+sub"),
                        (Operator::I32Const { .. }, Operator::I32Shl) => Some("i32.const+shl"),
                        (Operator::I32Const { .. }, Operator::I32ShrU) => Some("i32.const+shru"),
                        (Operator::I32Const { .. }, Operator::I32ShrS) => Some("i32.const+shrs"),
                        (Operator::I32Const { .. }, Operator::I32Eq) => Some("i32.const+eq"),
                        (Operator::I32Const { .. }, Operator::I32Ne) => Some("i32.const+ne"),
                        (Operator::I32Const { .. }, Operator::I32LtS) => Some("i32.const+lts"),
                        (Operator::I32Const { .. }, Operator::I32Eqz) => Some("i32.const+eqz"),
                        (Operator::I64Const { .. }, Operator::I64Add) => Some("i64.const+add"),
                        (Operator::I64Const { .. }, Operator::I64And) => Some("i64.const+and"),
                        (Operator::I64Const { .. }, Operator::I64Or) => Some("i64.const+or"),
                        (Operator::LocalGet { .. }, Operator::LocalSet { .. }) => Some("local.get+set"),
                        (Operator::LocalGet { .. }, Operator::LocalTee { .. }) => Some("local.get+tee"),
                        _ => None,
                    };
                    if let Some(n) = name {
                        *patterns.entry(n.to_string()).or_default() += 1;
                        if let Operator::I32Const { value } = &w[0]
                            && (*value == 0 || *value == 1 || *value == -1)
                        {
                                *i32const_then
                                    .entry(match &w[1] {
                                        Operator::I32Add => "add",
                                        Operator::I32Mul => "mul",
                                        Operator::I32And => "and",
                                        Operator::I32Or => "or",
                                        Operator::I32Xor => "xor",
                                        Operator::I32Sub => "sub",
                                        Operator::I32Shl => "shl",
                                        _ => "other",
                                    })
                                    .or_default() += 1;
                        }
                    }
                }
            }
        }
        println!("  adjacent pairs scanned (approx): windows total={total}");
        let mut p: Vec<_> = patterns.into_iter().collect();
        p.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (k, v) in p.into_iter().take(15) {
            println!("    {k:20} {v}");
        }
        println!("  i32.const(0/1/-1)+binop: {i32const_then:?}");

        // Body length histogram
        let mut hist = [0u32; 12];
        let mut bytes_hist = vec![0u64; 16]; // log2 buckets of body size
        let mut total_body = 0u64;
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload? {
                let r = body.range();
                let len = r.end - r.start;
                total_body += len;
                let bucket = (63 - len.leading_zeros()).min(15) as usize;
                bytes_hist[bucket] += len;
                let ops = body.get_operators_reader()?.into_iter().count() as u32;
                let b = (ops.min(11)) as usize;
                hist[b] += 1;
            }
        }
        println!("  body op-count hist (0-10, 11+ last): {hist:?}");
        println!("  body bytes by log2 bucket: {bytes_hist:?} total={total_body}");

        // Data section: how much is zeros? passive vs active
        let mut active_bytes = 0u64;
        let mut passive_bytes = 0u64;
        let mut active_zero = 0u64;
        let mut segs = 0u32;
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::DataSection(reader) = payload? {
                for d in reader {
                    let d = d?;
                    segs += 1;
                    let z = d.data.iter().filter(|&&b| b == 0).count() as u64;
                    match d.kind {
                        wasmparser::DataKind::Active { .. } => {
                            active_bytes += d.data.len() as u64;
                            active_zero += z;
                        }
                        wasmparser::DataKind::Passive => {
                            passive_bytes += d.data.len() as u64;
                        }
                    }
                }
            }
        }
        println!(
            "  data: {segs} segs, active={active_bytes} (zeros={active_zero}), passive={passive_bytes}"
        );

        // Function index distribution in element section - how many unique funcs referenced
        let mut elem_funcs = std::collections::HashSet::new();
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::ElementSection(reader) = payload? {
                for el in reader {
                    let el = el?;
                    if let wasmparser::ElementItems::Functions(items) = el.items {
                        for f in items {
                            elem_funcs.insert(f?);
                        }
                    }
                }
            }
        }
        println!("  element unique funcs: {}", elem_funcs.len());
    }
    Ok(())
}
