use anyhow::{bail, Result};
use std::collections::{HashMap, VecDeque};
use wasmparser::{
    CompositeInnerType, DataKind, ElementItems, Encoding, ExternalKind, FuncType, Operator,
    Parser, Payload, TypeRef, ValType,
};

pub fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "datacount",
        13 => "tag",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FuncSig {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

impl FuncSig {
    fn from_func_type(ft: &FuncType) -> Self {
        Self {
            params: ft.params().to_vec(),
            results: ft.results().to_vec(),
        }
    }
}

impl std::fmt::Display for FuncSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(")?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{p:?}")?;
        }
        write!(f, ")")?;
        if !self.results.is_empty() {
            write!(f, " -> ")?;
            for (i, r) in self.results.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{r:?}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    Func(FuncSig),
    FuncExact(FuncSig),
    Table(String),
    Memory(String),
    Global(String),
    Tag(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub kind: ExternalKind,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct SectionStat {
    pub id: u8,
    pub size: u64,
    pub custom_name: Option<String>,
}

impl SectionStat {
    pub fn name(&self) -> &'static str {
        if self.custom_name.is_some() {
            "custom"
        } else {
            section_name(self.id)
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataSegInfo {
    pub active: bool,
    /// References from function bodies that survive DCE.
    pub refs_live: usize,
    /// References from all function bodies.
    pub refs_all: usize,
    /// Index of an earlier identical active segment, if this is a duplicate.
    pub dup_of: Option<usize>,
    /// `[start, end)` in memory for active segments with a constant offset.
    pub range: Option<(u64, u64)>,
    /// Active segment whose bytes are all zero (no-op on zero-initialized memory
    /// unless a non-zero segment overlaps it).
    pub all_zero: bool,
}

#[derive(Debug)]
pub struct Analysis {
    pub sections: Vec<SectionStat>,
    pub func_types: Vec<Option<FuncSig>>,
    pub n_func_imports: u32,
    pub defined_types: Vec<u32>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub start: Option<u32>,
    pub has_data_count: bool,
    pub imported_funcref_global: bool,
    /// Raw body bytes per defined function.
    pub bodies: Vec<Vec<u8>>,
    /// Call/ref edges per defined function (full function indices).
    pub edges: Vec<Vec<u32>>,
    /// Reachability from exports/start/element segments/global initializers.
    pub live: Vec<bool>,
    pub roots_count: usize,
    /// Dedupe representative per defined function (first byte-identical peer with same type).
    pub reps: Vec<u32>,
    pub unreachable_count: usize,
    pub dup_count: usize,
    pub data: Vec<DataSegInfo>,
    /// Number of rec groups in the type section (index space for new types).
    pub n_types: u32,
    pub total_code_bytes: u64,
    pub total_data_bytes: u64,
    pub custom_bytes: u64,
    pub module_bytes: u64,
}

impl Analysis {
    pub fn n_defined(&self) -> usize {
        self.bodies.len()
    }

    pub fn n_functions(&self) -> usize {
        self.n_func_imports as usize + self.bodies.len()
    }

    pub fn custom_sections(&self) -> impl Iterator<Item = &SectionStat> {
        self.sections.iter().filter(|s| s.custom_name.is_some())
    }

    pub fn unused_data_count(&self) -> usize {
        self.data
            .iter()
            .filter(|d| !d.active && d.refs_all == 0)
            .count()
    }

    pub fn duplicate_active_data_count(&self) -> usize {
        self.data.iter().filter(|d| d.dup_of.is_some()).count()
    }
}

pub fn analyze(bytes: &[u8]) -> Result<Analysis> {
    let mut a = Analysis {
        sections: Vec::new(),
        func_types: Vec::new(),
        n_func_imports: 0,
        defined_types: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        start: None,
        has_data_count: false,
        imported_funcref_global: false,
        bodies: Vec::new(),
        edges: Vec::new(),
        live: Vec::new(),
        roots_count: 0,
        reps: Vec::new(),
        unreachable_count: 0,
        dup_count: 0,
        data: Vec::new(),
        n_types: 0,
        total_code_bytes: 0,
        total_data_bytes: 0,
        custom_bytes: 0,
        module_bytes: bytes.len() as u64,
    };

    let mut roots: Vec<u32> = Vec::new();
    let mut body_edges: Vec<Vec<u32>> = Vec::new();
    let mut body_datarefs: Vec<Vec<u32>> = Vec::new();
    let mut all_live = false;

    // Data segment duplicate detection: key = (memory, offset expr bytes, data len).
    let mut active_map: HashMap<(u32, Vec<u8>, usize, u64), usize> = HashMap::new();

    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::Version { encoding, .. } => {
                if encoding == Encoding::Component {
                    bail!("component-model modules are not supported yet");
                }
            }
            Payload::TypeSection(reader) => {
                let range = reader.range();
                for rec in reader {
                    let rec = rec?;
                    a.n_types += 1;
                    for sub in rec.into_types() {
                        let sig = match &sub.composite_type.inner {
                            CompositeInnerType::Func(ft) => Some(FuncSig::from_func_type(ft)),
                            _ => None,
                        };
                        a.func_types.push(sig);
                    }
                }
                a.sections.push(SectionStat {
                    id: 1,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::ImportSection(reader) => {
                let range = reader.range();
                for imp in reader.into_imports() {
                    let imp = imp?;
                    let sig = |t: u32| {
                        a.func_types
                            .get(t as usize)
                            .cloned()
                            .flatten()
                            .unwrap_or(FuncSig {
                                params: Vec::new(),
                                results: Vec::new(),
                            })
                    };
                    let kind = match imp.ty {
                        TypeRef::Func(t) => {
                            a.n_func_imports += 1;
                            ImportKind::Func(sig(t))
                        }
                        TypeRef::FuncExact(t) => {
                            a.n_func_imports += 1;
                            ImportKind::FuncExact(sig(t))
                        }
                        TypeRef::Table(tt) => ImportKind::Table(format!("{tt:?}")),
                        TypeRef::Memory(mt) => ImportKind::Memory(format!("{mt:?}")),
                        TypeRef::Global(gt) => {
                            // Conservative: a host-provided reference global can
                            // carry function references the module cannot track.
                            if matches!(gt.content_type, ValType::Ref(_)) {
                                all_live = true;
                            }
                            ImportKind::Global(format!("{gt:?}"))
                        }
                        TypeRef::Tag(t) => ImportKind::Tag(format!("{t:?}")),
                    };
                    a.imports.push(ImportInfo {
                        module: imp.module.to_string(),
                        name: imp.name.to_string(),
                        kind,
                    });
                }
                a.sections.push(SectionStat {
                    id: 2,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::FunctionSection(reader) => {
                let range = reader.range();
                for t in reader {
                    a.defined_types.push(t?);
                }
                a.sections.push(SectionStat {
                    id: 3,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::GlobalSection(reader) => {
                let range = reader.range();
                for g in reader {
                    let g = g?;
                    scan_const_refs(&g.init_expr, &mut roots);
                }
                a.sections.push(SectionStat {
                    id: 6,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::ExportSection(reader) => {
                let range = reader.range();
                for e in reader {
                    let e = e?;
                    if matches!(e.kind, ExternalKind::Func | ExternalKind::FuncExact) {
                        roots.push(e.index);
                    }
                    a.exports.push(ExportInfo {
                        name: e.name.to_string(),
                        kind: e.kind,
                        index: e.index,
                    });
                }
                a.sections.push(SectionStat {
                    id: 7,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::StartSection { func, range } => {
                a.start = Some(func);
                roots.push(func);
                a.sections.push(SectionStat {
                    id: 8,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::ElementSection(reader) => {
                let range = reader.range();
                for el in reader {
                    let el = el?;
                    match el.items {
                        ElementItems::Functions(items) => {
                            for f in items {
                                roots.push(f?);
                            }
                        }
                        ElementItems::Expressions(_, exprs) => {
                            for ex in exprs {
                                let ex = ex?;
                                scan_const_refs(&ex, &mut roots);
                            }
                        }
                    }
                }
                a.sections.push(SectionStat {
                    id: 9,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::DataCountSection { count, range } => {
                a.has_data_count = true;
                let _ = count;
                a.sections.push(SectionStat {
                    id: 12,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::CodeSectionStart { range, .. } => {
                a.sections.push(SectionStat {
                    id: 10,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::CodeSectionEntry(body) => {
                let r = body.range();
                let start = r.start as usize;
                let end = r.end as usize;
                a.bodies.push(bytes[start..end].to_vec());
                a.total_code_bytes += r.end - r.start;

                let mut ops = body.get_operators_reader()?;
                let mut edges = Vec::new();
                let mut datarefs = Vec::new();
                while !ops.eof() {
                    match ops.read()? {
                        Operator::Call { function_index }
                        | Operator::ReturnCall { function_index }
                        | Operator::RefFunc { function_index } => edges.push(function_index),
                        Operator::MemoryInit { data_index, .. } => datarefs.push(data_index),
                        Operator::DataDrop { data_index } => datarefs.push(data_index),
                        Operator::ArrayNewData {
                            array_data_index, ..
                        } => datarefs.push(array_data_index),
                        Operator::ArrayInitData {
                            array_data_index, ..
                        } => datarefs.push(array_data_index),
                        _ => {}
                    }
                }
                body_edges.push(edges);
                body_datarefs.push(datarefs);
            }
            Payload::DataSection(reader) => {
                let range = reader.range();
                let mut data_ranges: Vec<(usize, usize)> = Vec::new();
                for d in reader {
                    let d = d?;
                    a.total_data_bytes += d.data.len() as u64;
                    let data_off = d.data.as_ptr() as usize - bytes.as_ptr() as usize;
                    data_ranges.push((data_off, data_off + d.data.len()));

                    let all_zero = d.data.iter().all(|&b| b == 0);
                    let (active, mem_range, dup_of) = match &d.kind {
                        DataKind::Active {
                            memory_index,
                            offset_expr,
                        } => {
                            let rng = offset_expr.get_binary_reader().range();
                            let offset_bytes = &bytes[rng.start as usize..rng.end as usize];
                            let offset = eval_const_u64(offset_expr);
                            let mem_range =
                                offset.map(|o| (o, o + d.data.len() as u64));
                            let key = (
                                *memory_index,
                                offset_bytes.to_vec(),
                                d.data.len(),
                                fnv64(d.data),
                            );
                            let dup_of = match active_map.get(&key) {
                                Some(&first) => {
                                    let (s, e) = data_ranges[first];
                                    if &bytes[s..e] == d.data {
                                        Some(first)
                                    } else {
                                        None
                                    }
                                }
                                None => {
                                    active_map.insert(key, a.data.len());
                                    None
                                }
                            };
                            (true, mem_range, dup_of)
                        }
                        DataKind::Passive => (false, None, None),
                    };
                    a.data.push(DataSegInfo {
                        active,
                        refs_live: 0,
                        refs_all: 0,
                        dup_of,
                        range: mem_range,
                        all_zero: active && all_zero,
                    });
                }
                a.sections.push(SectionStat {
                    id: 11,
                    size: range.end - range.start,
                    custom_name: None,
                });
            }
            Payload::CustomSection(c) => {
                let rng = c.range();
                let size = rng.end - rng.start;
                a.custom_bytes += size;
                a.sections.push(SectionStat {
                    id: 0,
                    size,
                    custom_name: Some(c.name().to_string()),
                });
            }
            Payload::End(_) => {}
            other => {
                if let Some((id, range)) = other.as_section() {
                    a.sections.push(SectionStat {
                        id,
                        size: range.end - range.start,
                        custom_name: None,
                    });
                }
            }
        }
    }

    if a.defined_types.len() != a.bodies.len() {
        bail!(
            "internal: function/code section length mismatch ({} vs {})",
            a.defined_types.len(),
            a.bodies.len()
        );
    }

    a.imported_funcref_global = all_live;
    a.edges = body_edges;

    // Reachability.
    let n_def = a.bodies.len();
    let space = a.n_func_imports as usize + n_def;
    let mut live = vec![false; n_def];
    if all_live {
        live.fill(true);
        a.roots_count = space;
    } else {
        roots.retain(|&r| (r as usize) < space);
        roots.sort_unstable();
        roots.dedup();
        a.roots_count = roots.len();

        let mut seen = vec![false; space];
        let mut queue: VecDeque<u32> = VecDeque::new();
        for r in &roots {
            seen[*r as usize] = true;
            queue.push_back(*r);
        }
        while let Some(i) = queue.pop_front() {
            if i < a.n_func_imports {
                continue;
            }
            let d = i as usize - a.n_func_imports as usize;
            live[d] = true;
            for &t in &a.edges[d] {
                let ti = t as usize;
                if ti < space && !seen[ti] {
                    seen[ti] = true;
                    queue.push_back(t);
                }
            }
        }
    }
    a.unreachable_count = live.iter().filter(|x| !**x).count();
    a.live = live;

    // Dedupe representatives: first byte-identical body with same type index.
    let mut reps: Vec<u32> = (0..n_def as u32).collect();
    let mut groups: HashMap<(u32, usize), Vec<u32>> = HashMap::new();
    for i in 0..n_def {
        let key = (a.defined_types[i], a.bodies[i].len());
        groups.entry(key).or_default().push(i as u32);
    }
    for members in groups.values() {
        for k in 0..members.len() {
            let i = members[k] as usize;
            for &j in &members[..k] {
                if a.bodies[i] == a.bodies[j as usize] {
                    reps[i] = j;
                    break;
                }
            }
        }
    }
    a.dup_count = reps
        .iter()
        .enumerate()
        .filter(|pair| *pair.1 as usize != pair.0)
        .count();
    a.reps = reps;

    // Data segment reference counts.
    let mut refs_live = vec![0usize; a.data.len()];
    let mut refs_all = vec![0usize; a.data.len()];
    for (i, datarefs) in body_datarefs.iter().enumerate() {
        for &di in datarefs {
            if let Some(slot) = refs_all.get_mut(di as usize) {
                *slot += 1;
                if a.live[i] {
                    refs_live[di as usize] += 1;
                }
            }
        }
    }
    for (i, seg) in a.data.iter_mut().enumerate() {
        seg.refs_live = refs_live[i];
        seg.refs_all = refs_all[i];
    }

    Ok(a)
}

fn scan_const_refs(init_expr: &wasmparser::ConstExpr<'_>, roots: &mut Vec<u32>) {
    let mut ops = init_expr.get_operators_reader();
    while !ops.eof() {
        match ops.read() {
            Ok(Operator::RefFunc { function_index }) => roots.push(function_index),
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

/// Evaluate a simple constant offset expression (`i32.const` / `i64.const` only).
fn eval_const_u64(expr: &wasmparser::ConstExpr<'_>) -> Option<u64> {
    let mut ops = expr.get_operators_reader();
    let mut val = None;
    while !ops.eof() {
        match ops.read().ok()? {
            Operator::I32Const { value } => val = Some(value as u32 as u64),
            Operator::I64Const { value } => val = Some(value as u64),
            Operator::End => break,
            _ => return None,
        }
    }
    val
}

fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}
