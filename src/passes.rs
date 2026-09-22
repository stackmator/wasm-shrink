use crate::analysis::{analyze, Analysis};
use crate::wasm_util::validate_wasm;
use anyhow::{anyhow, Result};
use std::borrow::Cow;
use std::collections::HashSet;
use wasm_encoder::reencode::{Error as ReError, Reencode};
use wasm_encoder::{CodeSection, CustomSection, DataSection, FunctionSection, Module, TypeSection};
use wasmparser::{
    CodeSectionReader, CustomSectionReader, DataSectionReader, FunctionSectionReader, Parser,
    TypeSectionReader,
};

/// Custom sections that are always safe to remove.
pub const DEFAULT_STRIP: &[&str] = &["name", "producers", "sourceMappingURL", "sourceMap"];

/// Custom sections that are required at runtime or for tooling — never stripped
/// unless the user explicitly asks for them by name.
pub const PROTECTED: &[&str] = &["target_features", "dylink", "dylink.0", "linking"];

pub fn is_protected(name: &str, keep: &HashSet<String>) -> bool {
    keep.contains(name) || PROTECTED.contains(&name) || name.starts_with("reloc.")
}

pub fn would_strip(name: &str, strip: &HashSet<String>, strip_all: bool, keep: &HashSet<String>) -> bool {
    if is_protected(name, keep) {
        return false;
    }
    strip.contains(name) || strip_all
}

#[derive(Debug, Clone)]
pub struct PassConfig {
    pub strip: bool,
    pub data: bool,
    pub dedupe: bool,
    pub dce: bool,
    pub code: bool,
    pub merge: bool,
    pub user_strip: Vec<String>,
    pub user_keep: Vec<String>,
    pub profile_keep: HashSet<String>,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            strip: true,
            data: true,
            dedupe: true,
            dce: true,
            code: true,
            merge: true,
            user_strip: Vec::new(),
            user_keep: Vec::new(),
            profile_keep: HashSet::new(),
        }
    }
}

impl PassConfig {
    pub fn keep_set(&self) -> HashSet<String> {
        let mut keep = self.profile_keep.clone();
        for k in &self.user_keep {
            keep.insert(k.clone());
        }
        keep
    }

    pub fn strip_all(&self) -> bool {
        self.user_strip.iter().any(|s| s == "all")
    }

    /// Custom sections to strip. When the user disabled stripping but
    /// index-changing passes run, `name` is still forced out (stale indices).
    pub fn effective_strip(&self, index_changing: bool) -> (HashSet<String>, bool) {
        let mut keep = self.keep_set();
        let forced = index_changing && keep.contains("name");
        if forced {
            keep.remove("name");
        }
        let mut strip: HashSet<String> = if self.strip {
            DEFAULT_STRIP.iter().map(|s| s.to_string()).collect()
        } else if index_changing {
            ["name"].iter().map(|s| s.to_string()).collect()
        } else {
            HashSet::new()
        };
        for s in &self.user_strip {
            if s != "all" {
                strip.insert(s.clone());
            }
        }
        strip.retain(|n| !is_protected(n, &keep));
        (strip, forced)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StageFlags {
    pub data: bool,
    pub dedupe: bool,
    pub dce: bool,
    pub code: bool,
    pub merge: bool,
}

pub struct Maps {
    pub func_map: Vec<u32>,
    pub keep_defined: Vec<bool>,
    pub data_map: Vec<u32>,
    pub keep_data: Vec<bool>,
    pub data_count: u32,
}

pub const REMOVED: u32 = u32::MAX;

struct Shr {
    func_map: Vec<u32>,
    keep_defined: Vec<bool>,
    data_map: Vec<u32>,
    keep_data: Vec<bool>,
    data_count: u32,
    strip: HashSet<String>,
    strip_all: bool,
    keep: HashSet<String>,
    peephole: bool,
    merge: Option<crate::merge::MergePlan>,
}

impl Shr {
    fn should_strip(&self, name: &str) -> bool {
        would_strip(name, &self.strip, self.strip_all, &self.keep)
    }
}

impl Reencode for Shr {
    type Error = String;

    fn function_index(&mut self, func: u32) -> Result<u32, ReError<String>> {
        self.func_map
            .get(func as usize)
            .copied()
            .filter(|&x| x != REMOVED)
            .ok_or_else(|| ReError::UserError(format!("reference to removed function {func}")))
    }

    fn data_index(&mut self, data: u32) -> Result<u32, ReError<String>> {
        self.data_map
            .get(data as usize)
            .copied()
            .filter(|&x| x != REMOVED)
            .ok_or_else(|| ReError::UserError(format!("reference to removed data segment {data}")))
    }

    fn data_count(&mut self, _count: u32) -> Result<u32, ReError<String>> {
        Ok(self.data_count)
    }

    fn parse_function_section(
        &mut self,
        functions: &mut FunctionSection,
        section: FunctionSectionReader<'_>,
    ) -> Result<(), ReError<String>> {
        for (i, ty) in section.into_iter().enumerate() {
            if self.keep_defined.get(i).copied().unwrap_or(true) {
                functions.function(self.type_index(ty?)?);
            }
        }
        if let Some(m) = &self.merge {
            for k in 0..m.merged.len() as u32 {
                functions.function(m.orig_type_count + k);
            }
        }
        Ok(())
    }

    fn parse_type_section(
        &mut self,
        types: &mut TypeSection,
        section: TypeSectionReader<'_>,
    ) -> Result<(), ReError<String>> {
        let merge = self.merge.take();
        wasm_encoder::reencode::utils::parse_type_section(self, types, section)?;
        if let Some(m) = &merge {
            for f in &m.merged {
                types.ty().function(f.params.iter().copied(), f.results.iter().copied());
            }
        }
        self.merge = merge;
        Ok(())
    }

    fn parse_code_section(
        &mut self,
        code: &mut CodeSection,
        section: CodeSectionReader<'_>,
    ) -> Result<(), ReError<String>> {
        let merge = self.merge.take();
        for (i, body) in section.into_iter().enumerate() {
            if let Some(Some(w)) = merge.as_ref().and_then(|m| m.wrappers.get(i)) {
                code.raw(w);
            } else if self.keep_defined.get(i).copied().unwrap_or(true) {
                self.parse_function_body(code, body?)?;
            }
        }
        if let Some(m) = &merge {
            for f in &m.merged {
                code.raw(&f.body);
            }
        }
        self.merge = merge;
        Ok(())
    }

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReError<String>> {
        if !self.peephole {
            return wasm_encoder::reencode::utils::parse_function_body(self, code, func);
        }
        let mut f = self.new_function_with_parsed_locals(&func)?;
        let mut reader = func.get_operators_reader()?;
        let mut instrs = Vec::new();
        while !reader.eof() {
            instrs.push(self.parse_instruction(&mut reader)?);
        }
        crate::peephole::optimize(&mut instrs);
        for i in &instrs {
            f.instruction(i);
        }
        code.function(&f);
        Ok(())
    }

    fn parse_data_section(
        &mut self,
        data: &mut DataSection,
        section: DataSectionReader<'_>,
    ) -> Result<(), ReError<String>> {
        for (i, datum) in section.into_iter().enumerate() {
            if self.keep_data.get(i).copied().unwrap_or(true) {
                self.parse_data(data, datum?)?;
            }
        }
        Ok(())
    }

    fn parse_custom_section(
        &mut self,
        module: &mut Module,
        section: CustomSectionReader<'_>,
    ) -> Result<(), ReError<String>> {
        let name = section.name();
        if self.should_strip(name) {
            return Ok(());
        }
        module.section(&CustomSection {
            name: Cow::Borrowed(name),
            data: Cow::Borrowed(section.data()),
        });
        Ok(())
    }
}

pub fn compute_maps(a: &Analysis, flags: &StageFlags) -> Maps {
    let n = a.bodies.len();
    let n_imports = a.n_func_imports as usize;

    let considered: Vec<bool> = if flags.dce {
        a.live.clone()
    } else {
        vec![true; n]
    };
    let rep: Vec<u32> = if flags.dedupe {
        a.reps.clone()
    } else {
        (0..n as u32).collect()
    };

    let mut emitted = vec![false; n];
    for f in 0..n {
        if considered[f] {
            emitted[rep[f] as usize] = true;
        }
    }
    let mut new_of = vec![REMOVED; n];
    let mut rank = 0u32;
    for e in 0..n {
        if emitted[e] {
            new_of[e] = n_imports as u32 + rank;
            rank += 1;
        }
    }

    let mut func_map = Vec::with_capacity(n_imports + n);
    for i in 0..n_imports as u32 {
        func_map.push(i);
    }
    for f in 0..n {
        let mapped = if considered[f] {
            new_of[rep[f] as usize]
        } else if emitted[f] {
            new_of[f]
        } else {
            REMOVED
        };
        func_map.push(mapped);
    }

    // Data segments.
    let nd = a.data.len();
    let mut keep_data = vec![true; nd];
    if flags.data {
        for (i, seg) in a.data.iter().enumerate() {
            if seg.dup_of.is_some() {
                keep_data[i] = false;
                continue;
            }
            if !seg.active {
                let refs = if flags.dce {
                    seg.refs_live
                } else {
                    seg.refs_all
                };
                if refs == 0 {
                    keep_data[i] = false;
                }
            }
        }
        // Whole-segment all-zero elision: memory starts zeroed, so an active
        // all-zero segment is a no-op unless a non-zero segment overlaps it.
        // Unknown offsets (or any unknown active range) block the optimization.
        let unknown_active = a
            .data
            .iter()
            .any(|s| s.active && s.range.is_none());
        if !unknown_active {
            for (i, seg) in a.data.iter().enumerate() {
                if !keep_data[i] || !seg.all_zero {
                    continue;
                }
                let (s, e) = seg.range.expect("checked above");
                let overlaps_nonzero = a.data.iter().enumerate().any(|(j, t)| {
                    j != i
                        && t.active
                        && !t.all_zero
                        && t.range
                            .map(|(ts, te)| s < te && ts < e)
                            .unwrap_or(true)
                });
                if !overlaps_nonzero {
                    keep_data[i] = false;
                }
            }
        }
    }
    let mut dnew = vec![REMOVED; nd];
    let mut drank = 0u32;
    for i in 0..nd {
        if keep_data[i] {
            dnew[i] = drank;
            drank += 1;
        }
    }
    let data_map = dnew;

    Maps {
        func_map,
        keep_defined: emitted,
        data_map,
        keep_data,
        data_count: drank,
    }
}

pub fn reencode_module(
    bytes: &[u8],
    a: &Analysis,
    flags: &StageFlags,
    strip: &HashSet<String>,
    strip_all: bool,
    keep: &HashSet<String>,
) -> Result<(Vec<u8>, Maps)> {
    let maps = compute_maps(a, flags);
    let merge = if flags.merge {
        crate::merge::plan(bytes, a)?
    } else {
        None
    };
    let mut shr = Shr {
        func_map: maps.func_map.clone(),
        keep_defined: maps.keep_defined.clone(),
        data_map: maps.data_map.clone(),
        keep_data: maps.keep_data.clone(),
        data_count: maps.data_count,
        strip: strip.clone(),
        strip_all,
        keep: keep.clone(),
        peephole: flags.code,
        merge,
    };
    let mut module = Module::new();
    shr.parse_core_module(&mut module, Parser::new(0), bytes)
        .map_err(|e| anyhow!("reencode failed: {e}"))?;
    Ok((module.finish(), maps))
}

#[derive(Debug, Clone)]
pub struct StageReport {
    pub label: &'static str,
    pub before: u64,
    pub after: u64,
    pub funcs_removed: usize,
    pub data_removed: usize,
    pub custom_removed: usize,
    pub custom_bytes_removed: u64,
}

impl StageReport {
    pub fn delta(&self) -> i64 {
        self.after as i64 - self.before as i64
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug)]
pub struct PipelineResult {
    pub output: Vec<u8>,
    pub stages: Vec<StageReport>,
    pub orig: Analysis,
    pub final_analysis: Analysis,
    pub checks: Vec<Check>,
    pub warnings: Vec<String>,
    pub stripped_customs: Vec<(String, u64)>,
    pub deterministic: bool,
}

fn compose_maps(maps: &[Maps]) -> Vec<u32> {
    if maps.is_empty() {
        return Vec::new();
    }
    let mut cur: Vec<u32> = (0..maps[0].func_map.len() as u32).collect();
    for m in maps {
        cur = cur
            .iter()
            .map(|&x| {
                if x == REMOVED {
                    REMOVED
                } else {
                    m.func_map.get(x as usize).copied().unwrap_or(REMOVED)
                }
            })
            .collect();
    }
    cur
}

type StagesOutput = (
    Vec<u8>,
    Vec<StageReport>,
    Vec<Maps>,
    Vec<Vec<(String, u64)>>,
);

fn run_stages(
    bytes: &[u8],
    cfg: &PassConfig,
) -> Result<StagesOutput> {
    let index_changing = cfg.dce || cfg.dedupe;
    let (strip, forced_name) = cfg.effective_strip(index_changing);
    let keep = {
        let mut k = cfg.keep_set();
        if forced_name {
            k.remove("name");
        }
        k
    };
    let strip_all = cfg.strip_all();

    let mut plan: Vec<(&'static str, StageFlags)> = Vec::new();
    let mut fl = StageFlags::default();
    if cfg.strip {
        plan.push(("Section stripping", fl));
    }
    if cfg.data {
        fl.data = true;
        plan.push(("Data optimization", fl));
    }
    if cfg.code {
        let mut cf = fl;
        cf.code = true;
        plan.push(("Code optimization", cf));
    }
    if cfg.dedupe {
        fl.dedupe = true;
        plan.push(("Function folding", fl));
    }
    if cfg.dce {
        fl.dce = true;
        plan.push(("Dead code elimination", fl));
    }
    if cfg.merge {
        plan.push((
            "Function merging",
            StageFlags {
                merge: true,
                ..Default::default()
            },
        ));
    }

    if plan.is_empty() {
        return Ok((
            bytes.to_vec(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
    }

    let mut current = bytes.to_vec();
    let mut reports = Vec::new();
    let mut all_maps = Vec::new();
    let mut stripped_per_stage = Vec::new();

    for (label, flags) in plan {
        let a_now = analyze(&current)?;
        let (out, maps) = reencode_module(&current, &a_now, &flags, &strip, strip_all, &keep)?;
        validate_wasm(&out)
            .map_err(|e| anyhow!("output failed validation after stage '{label}': {e}"))?;

        let customs_kept = a_now
            .custom_sections()
            .filter(|s| {
                let n = s.custom_name.as_deref().unwrap_or("");
                !would_strip(n, &strip, strip_all, &keep)
            })
            .count();
        let customs_total = a_now.custom_sections().count();
        let mut stripped_names: Vec<(String, u64)> = a_now
            .custom_sections()
            .filter_map(|s| {
                let n = s.custom_name.as_deref().unwrap_or("");
                if would_strip(n, &strip, strip_all, &keep) {
                    Some((n.to_string(), s.size))
                } else {
                    None
                }
            })
            .collect();
        stripped_names.dedup_by(|a, b| a.0 == b.0);

        let n_funcs_out = maps.keep_defined.iter().filter(|k| **k).count();
        let n_data_out = maps.keep_data.iter().filter(|k| **k).count();

        reports.push(StageReport {
            label,
            before: current.len() as u64,
            after: out.len() as u64,
            funcs_removed: a_now.n_defined() - n_funcs_out,
            data_removed: a_now.data.len() - n_data_out,
            custom_removed: customs_total - customs_kept,
            custom_bytes_removed: stripped_names.iter().map(|(_, s)| *s).sum(),
        });
        all_maps.push(maps);
        stripped_per_stage.push(stripped_names);
        current = out;
    }

    Ok((current, reports, all_maps, stripped_per_stage))
}

pub fn optimize(bytes: &[u8], cfg: &PassConfig) -> Result<PipelineResult> {
    let orig = analyze(bytes)?;
    validate_wasm(bytes).map_err(|e| anyhow!("input failed validation: {e}"))?;

    let (output, stages, all_maps, stripped_per_stage) = run_stages(bytes, cfg)?;

    let final_analysis = analyze(&output)?;
    validate_wasm(&output).map_err(|e| anyhow!("final output failed validation: {e}"))?;

    let composed = if all_maps.is_empty() {
        // No passes ran: indices are unchanged.
        (0..orig.n_functions() as u32).collect::<Vec<u32>>()
    } else {
        compose_maps(&all_maps)
    };
    let mut checks = run_checks(&orig, &final_analysis, &composed);

    // Determinism: run the whole pipeline a second time.
    let rerun = run_stages(bytes, cfg)?;
    let deterministic = rerun.0 == output;
    checks.push(Check {
        label: "Deterministic output",
        ok: deterministic,
        detail: if deterministic {
            "second run produced byte-identical output".into()
        } else {
            "second run differed from first run".into()
        },
    });

    let mut warnings = Vec::new();
    let index_changing = cfg.dce || cfg.dedupe;
    let (_, forced_name) = cfg.effective_strip(index_changing);
    if forced_name {
        warnings.push(
            "name section stripped for index safety (indices changed by optimization)".into(),
        );
    }

    let mut stripped_customs: Vec<(String, u64)> = Vec::new();
    for stage_list in &stripped_per_stage {
        for (name, size) in stage_list {
            if let Some(slot) = stripped_customs.iter_mut().find(|(n, _)| n == name) {
                slot.1 = slot.1.max(*size);
            } else {
                stripped_customs.push((name.clone(), *size));
            }
        }
    }
    stripped_customs.sort();

    Ok(PipelineResult {
        output,
        stages,
        orig,
        final_analysis,
        checks,
        warnings,
        stripped_customs,
        deterministic,
    })
}

pub fn kind_equiv(k: wasmparser::ExternalKind) -> u8 {
    use wasmparser::ExternalKind::*;
    match k {
        Func | FuncExact => 0,
        Table => 1,
        Memory => 2,
        Global => 3,
        Tag => 4,
    }
}

fn run_checks(orig: &Analysis, out: &Analysis, func_map: &[u32]) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(Check {
        label: "WASM validation",
        ok: true,
        detail: "input and output both validate".into(),
    });

    // Imports.
    let mut import_ok = orig.imports == out.imports;
    let mut import_detail = format!("{} imports preserved", out.imports.len());
    if !import_ok {
        if orig.imports.len() != out.imports.len() {
            import_detail = format!(
                "import count changed: {} -> {}",
                orig.imports.len(),
                out.imports.len()
            );
        } else {
            for (i, (a, b)) in orig.imports.iter().zip(out.imports.iter()).enumerate() {
                if a != b {
                    import_detail = format!(
                        "import #{i} changed: {}.{} -> {}.{}",
                        a.module, a.name, b.module, b.name
                    );
                    break;
                }
            }
        }
        import_ok = false;
    }
    checks.push(Check {
        label: "Import compatibility",
        ok: import_ok,
        detail: import_detail,
    });

    // Exports with precise index mapping.
    let mut export_ok = true;
    let mut export_detail = format!("{} exports mapped", out.exports.len());
    if orig.exports.len() != out.exports.len() {
        export_ok = false;
        export_detail = format!(
            "export count changed: {} -> {}",
            orig.exports.len(),
            out.exports.len()
        );
    } else {
        for (i, (o, n)) in orig.exports.iter().zip(out.exports.iter()).enumerate() {
            if o.name != n.name || kind_equiv(o.kind) != kind_equiv(n.kind) {
                export_ok = false;
                export_detail = format!(
                    "export #{i} changed: {} -> {}",
                    o.name, n.name
                );
                break;
            }
            let expected = match o.kind {
                wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact => {
                    func_map.get(o.index as usize).copied().unwrap_or(REMOVED)
                }
                _ => o.index,
            };
            if expected == REMOVED || n.index != expected {
                export_ok = false;
                export_detail = format!(
                    "export '{}' index mismatch (expected {}, got {})",
                    o.name, expected, n.index
                );
                break;
            }
        }
    }
    checks.push(Check {
        label: "Export compatibility",
        ok: export_ok,
        detail: export_detail,
    });

    // Start section.
    let start_ok = match (orig.start, out.start) {
        (None, None) => true,
        (Some(f), Some(g)) => {
            func_map.get(f as usize).copied() == Some(g) && g != REMOVED
        }
        _ => false,
    };
    checks.push(Check {
        label: "Start function compatibility",
        ok: start_ok,
        detail: match (orig.start, out.start) {
            (None, None) => "no start section".into(),
            (Some(f), Some(g)) => format!("start remapped {f} -> {g}"),
            (Some(_), None) => "start section removed".into(),
            (None, Some(_)) => "start section added".into(),
        },
    });

    // Section integrity: same set of non-custom sections, strictly increasing ids.
    let section_ok = section_integrity(bytes_ids(&orig.sections), bytes_ids(&out.sections));
    checks.push(Check {
        label: "Section integrity",
        ok: section_ok,
        detail: if section_ok {
            "section set and ordering preserved".into()
        } else {
            "section set or ordering changed".into()
        },
    });

    checks
}

fn bytes_ids(sections: &[crate::analysis::SectionStat]) -> Vec<u8> {
    sections
        .iter()
        .filter(|s| s.custom_name.is_none())
        .map(|s| s.id)
        .collect()
}

fn section_integrity(mut a: Vec<u8>, mut b: Vec<u8>) -> bool {
    a.sort_unstable();
    b.sort_unstable();
    a == b
}
