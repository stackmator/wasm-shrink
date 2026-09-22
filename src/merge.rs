use anyhow::{anyhow, Result};
use std::collections::HashMap;
use wasm_encoder::reencode::{Error as ReError, Reencode};
use wasm_encoder::{
    BlockType, CodeSection, Encode, Function, Ieee32, Ieee64, Instruction, Module, ValType,
};
use wasmparser::{FunctionBody, Parser, ValType as PValType};

use crate::analysis::Analysis;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConstKind {
    I32,
    I64,
    F32,
    F64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConstVal {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
}

impl ConstVal {
    fn kind(self) -> ConstKind {
        match self {
            ConstVal::I32(_) => ConstKind::I32,
            ConstVal::I64(_) => ConstKind::I64,
            ConstVal::F32(_) => ConstKind::F32,
            ConstVal::F64(_) => ConstKind::F64,
        }
    }
}

impl ConstKind {
    fn val_type(self) -> ValType {
        match self {
            ConstKind::I32 => ValType::I32,
            ConstKind::I64 => ValType::I64,
            ConstKind::F32 => ValType::F32,
            ConstKind::F64 => ValType::F64,
        }
    }
}

/// A parameterizable position in a function body.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Slot {
    Const(ConstVal),
    Call(u32),
}

/// A function body appended to the module as a merge target.
pub struct MergedFn {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
    pub body: Vec<u8>,
}

pub struct MergePlan {
    /// Per defined function of the input module: replacement wrapper body.
    pub wrappers: Vec<Option<Vec<u8>>>,
    pub merged: Vec<MergedFn>,
    pub orig_type_count: u32,
}

struct FnInfo {
    ty: u32,
    locals_key: Vec<u8>,
    key: Vec<u8>,
    locals: Vec<(u32, PValType)>,
    slots: Vec<Slot>,
    raw_len: u64,
    params: usize,
}

struct KeyCollect {
    defined_types: Vec<u32>,
    idx: usize,
    out: Vec<FnInfo>,
}

impl Reencode for KeyCollect {
    type Error = String;

    fn parse_function_body(
        &mut self,
        _code: &mut CodeSection,
        func: FunctionBody<'_>,
    ) -> Result<(), ReError<String>> {
        let mut locals = Vec::new();
        let mut locals_key = Vec::new();
        for pair in func.get_locals_reader()? {
            let (c, t) = pair?;
            locals_key.extend_from_slice(&c.to_le_bytes());
            locals_key.push(vt_code(t));
            locals.push((c, t));
        }
        let mut reader = func.get_operators_reader()?;
        let mut key = Vec::new();
        let mut slots = Vec::new();
        while !reader.eof() {
            let ins = self.parse_instruction(&mut reader)?;
            match &ins {
                Instruction::I32Const(v) => {
                    key.extend_from_slice(&[0x41, 0x00]);
                    slots.push(Slot::Const(ConstVal::I32(*v)));
                }
                Instruction::I64Const(v) => {
                    key.extend_from_slice(&[0x42, 0x00]);
                    slots.push(Slot::Const(ConstVal::I64(*v)));
                }
                Instruction::F32Const(v) => {
                    key.extend_from_slice(&[0x43, 0, 0, 0, 0]);
                    slots.push(Slot::Const(ConstVal::F32(v.bits())));
                }
                Instruction::F64Const(v) => {
                    key.extend_from_slice(&[0x44, 0, 0, 0, 0, 0, 0, 0, 0]);
                    slots.push(Slot::Const(ConstVal::F64(v.bits())));
                }
                Instruction::Call(t) => {
                    key.extend_from_slice(&[0x10, 0x00]);
                    slots.push(Slot::Call(*t));
                }
                _ => {
                    let mut v = Vec::new();
                    ins.encode(&mut v);
                    key.extend(v);
                }
            }
        }
        let raw_len = func.range().end - func.range().start;
        let ty = self.defined_types[self.idx];
        self.idx += 1;
        self.out.push(FnInfo {
            ty,
            locals_key,
            key,
            locals,
            slots,
            raw_len,
            params: 0,
        });
        Ok(())
    }
}

struct CallPlan {
    /// Sorted distinct call targets for this slot.
    targets: Vec<u32>,
    param_types: Vec<ValType>,
    result_types: Vec<ValType>,
    /// First local index of the spilled argument temporaries.
    temp_base: u32,
}

struct BuildTask {
    p: u32,
    d: u32,
    slot_map: Vec<Option<u32>>,
    rep_slots: Vec<Slot>,
    locals: Vec<(u32, PValType)>,
    extra_locals: Vec<ValType>,
    calls: HashMap<usize, CallPlan>,
}

struct BuildCollect {
    tasks: HashMap<usize, BuildTask>,
    idx: usize,
    out: HashMap<usize, Option<Vec<u8>>>,
}

impl Reencode for BuildCollect {
    type Error = String;

    fn parse_function_body(
        &mut self,
        _code: &mut CodeSection,
        func: FunctionBody<'_>,
    ) -> Result<(), ReError<String>> {
        let i = self.idx;
        self.idx += 1;
        let Some(task) = self.tasks.get(&i) else {
            return Ok(());
        };
        let p = task.p;
        let d = task.d;
        let slot_map = task.slot_map.clone();
        let rep_slots = task.rep_slots.clone();
        let rep_locals = task.locals.clone();
        let extra_locals = task.extra_locals.clone();
        let calls = task
            .calls
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    CallPlan {
                        targets: v.targets.clone(),
                        param_types: v.param_types.clone(),
                        result_types: v.result_types.clone(),
                        temp_base: v.temp_base,
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let mut locals = Vec::new();
        for (c, t) in &rep_locals {
            let Some(t) = to_enc(*t) else {
                self.out.insert(i, None);
                return Ok(());
            };
            locals.push((*c, t));
        }
        for t in &extra_locals {
            locals.push((1, *t));
        }
        let mut f = Function::new(locals);
        let mut reader = func.get_operators_reader()?;
        let mut ord = 0usize;
        while !reader.eof() {
            let ins = self.parse_instruction(&mut reader)?;
            match &ins {
                Instruction::I32Const(_)
                | Instruction::I64Const(_)
                | Instruction::F32Const(_)
                | Instruction::F64Const(_) => {
                    match slot_map.get(ord).copied().flatten() {
                        Some(pi) => {
                            f.instruction(&Instruction::LocalGet(p + pi));
                        }
                        None => match rep_slots.get(ord) {
                            Some(Slot::Const(c)) => {
                                f.instruction(&const_of(*c));
                            }
                            _ => {
                                self.out.insert(i, None);
                                return Ok(());
                            }
                        },
                    }
                    ord += 1;
                }
                Instruction::Call(_) => {
                    match slot_map.get(ord).copied().flatten() {
                        Some(pi) => {
                            let Some(plan) = calls.get(&ord) else {
                                self.out.insert(i, None);
                                return Ok(());
                            };
                            emit_call_slot(&mut f, plan, p + pi);
                        }
                        None => match rep_slots.get(ord) {
                            Some(Slot::Call(t)) => {
                                f.instruction(&Instruction::Call(*t));
                            }
                            _ => {
                                self.out.insert(i, None);
                                return Ok(());
                            }
                        },
                    }
                    ord += 1;
                }
                Instruction::LocalGet(x) => {
                    f.instruction(&Instruction::LocalGet(shift(*x, p, d)));
                }
                Instruction::LocalSet(x) => {
                    f.instruction(&Instruction::LocalSet(shift(*x, p, d)));
                }
                Instruction::LocalTee(x) => {
                    f.instruction(&Instruction::LocalTee(shift(*x, p, d)));
                }
                _ => {
                    f.instruction(&ins);
                }
            }
        }
        if ord != rep_slots.len() {
            self.out.insert(i, None);
        } else {
            self.out.insert(i, Some(f.into_raw_body()));
        }
        Ok(())
    }
}

fn emit_call_slot(f: &mut Function, plan: &CallPlan, sel: u32) {
    let a = plan.param_types.len() as u32;
    for j in (0..a).rev() {
        f.instruction(&Instruction::LocalSet(plan.temp_base + j));
    }
    let bt = block_type(&plan.result_types);
    emit_dispatch(f, &plan.targets, sel, plan.temp_base, a, bt, 0);
}

#[allow(clippy::too_many_arguments)]
fn emit_dispatch(
    f: &mut Function,
    targets: &[u32],
    sel: u32,
    temp_base: u32,
    a: u32,
    bt: BlockType,
    level: i32,
) {
    if targets.len() == 1 {
        for j in 0..a {
            f.instruction(&Instruction::LocalGet(temp_base + j));
        }
        f.instruction(&Instruction::Call(targets[0]));
        return;
    }
    f.instruction(&Instruction::LocalGet(sel));
    f.instruction(&Instruction::I32Const(level));
    f.instruction(&Instruction::I32Eq);
    f.instruction(&Instruction::If(bt));
    for j in 0..a {
        f.instruction(&Instruction::LocalGet(temp_base + j));
    }
    f.instruction(&Instruction::Call(targets[0]));
    f.instruction(&Instruction::Else);
    emit_dispatch(f, &targets[1..], sel, temp_base, a, bt, level + 1);
    f.instruction(&Instruction::End);
}

fn block_type(results: &[ValType]) -> BlockType {
    match results {
        [] => BlockType::Empty,
        [one] => BlockType::Result(*one),
        _ => BlockType::Empty,
    }
}

fn shift(i: u32, p: u32, d: u32) -> u32 {
    if i < p { i } else { i + d }
}

fn vt_code(t: PValType) -> u8 {
    match t {
        PValType::I32 => 0x7f,
        PValType::I64 => 0x7e,
        PValType::F32 => 0x7d,
        PValType::F64 => 0x7c,
        PValType::V128 => 0x7b,
        PValType::Ref(_) => 0x70,
    }
}

fn to_enc(t: PValType) -> Option<ValType> {
    match t {
        PValType::I32 => Some(ValType::I32),
        PValType::I64 => Some(ValType::I64),
        PValType::F32 => Some(ValType::F32),
        PValType::F64 => Some(ValType::F64),
        PValType::V128 => Some(ValType::V128),
        PValType::Ref(r) => {
            if r == wasmparser::RefType::FUNCREF {
                Some(ValType::FUNCREF)
            } else if r == wasmparser::RefType::EXTERNREF {
                Some(ValType::EXTERNREF)
            } else {
                None
            }
        }
    }
}

fn defined_sig(a: &Analysis, idx: u32) -> Option<(Vec<PValType>, Vec<PValType>)> {
    let ni = a.n_func_imports;
    if idx < ni {
        return None;
    }
    let d = (idx - ni) as usize;
    let ty = *a.defined_types.get(d)?;
    let ft = a.func_types.get(ty as usize)?.as_ref()?;
    Some((ft.params.clone(), ft.results.clone()))
}

pub fn plan(bytes: &[u8], a: &Analysis) -> Result<Option<MergePlan>> {
    let n_def = a.bodies.len();
    if n_def == 0 {
        return Ok(None);
    }

    // Pass 1: canonical key + slot sequence for every body.
    let mut kc = KeyCollect {
        defined_types: a.defined_types.clone(),
        idx: 0,
        out: Vec::with_capacity(n_def),
    };
    let mut sink = Module::new();
    kc.parse_core_module(&mut sink, Parser::new(0), bytes)
        .map_err(|e| anyhow!("merge analysis failed: {e}"))?;
    if kc.out.len() != n_def {
        return Ok(None);
    }
    let mut infos = kc.out;
    for info in infos.iter_mut() {
        info.params = a
            .func_types
            .get(info.ty as usize)
            .and_then(|t| t.as_ref())
            .map(|t| t.params.len())
            .unwrap_or(0);
    }

    // Group by (type, declared locals, canonical body).
    let mut group_of: HashMap<(u32, Vec<u8>, Vec<u8>), usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, info) in infos.iter().enumerate() {
        let k = (info.ty, info.locals_key.clone(), info.key.clone());
        match group_of.get(&k) {
            Some(&g) => groups[g].push(i),
            None => {
                let g = groups.len();
                group_of.insert(k, g);
                groups.push(vec![i]);
            }
        }
    }

    struct Cand {
        rep: usize,
        gid: usize,
        diff: Vec<usize>,
    }
    let mut cands: Vec<Cand> = Vec::new();
    for (gid, members) in groups.iter().enumerate() {
        if members.len() < 2 {
            continue;
        }
        let rep = members[0];
        let diff = diff_slots(members, &infos);
        if diff.is_empty() {
            continue;
        }
        // Every differing call slot must be liftable to a selector dispatch.
        if !call_slots_ok(members, &infos, &diff, a) {
            continue;
        }
        cands.push(Cand { rep, gid, diff });
    }
    if cands.is_empty() {
        return Ok(None);
    }

    // Build tasks and merged bodies for every candidate.
    let base_fn = a.n_functions() as u32;
    let base_ty = a.n_types;

    let mut tasks: HashMap<usize, BuildTask> = HashMap::new();
    for c in &cands {
        let info = &infos[c.rep];
        let p = info.params as u32;
        let d = c.diff.len() as u32;
        let l: u32 = info.locals.iter().map(|(n, _)| *n).sum();
        let mut cum = 0u32;
        let mut extra_locals = Vec::new();
        let mut calls = HashMap::new();
        for &ord in &c.diff {
            if let Slot::Call(_) = info.slots[ord] {
                let targets = call_targets(&groups[c.gid], &infos, ord);
                let (params, results) = defined_sig(a, targets[0]).expect("checked");
                let param_types: Vec<ValType> =
                    params.iter().filter_map(|t| to_enc(*t)).collect();
                let result_types: Vec<ValType> =
                    results.iter().filter_map(|t| to_enc(*t)).collect();
                let temp_base = p + d + l + cum;
                cum += param_types.len() as u32;
                extra_locals.extend(param_types.iter().copied());
                calls.insert(
                    ord,
                    CallPlan {
                        targets,
                        param_types,
                        result_types,
                        temp_base,
                    },
                );
            }
        }
        let slot_map: Vec<Option<u32>> = (0..info.slots.len())
            .map(|o| c.diff.iter().position(|&x| x == o).map(|q| q as u32))
            .collect();
        tasks.insert(
            c.rep,
            BuildTask {
                p,
                d,
                slot_map,
                rep_slots: info.slots.clone(),
                locals: info.locals.clone(),
                extra_locals,
                calls,
            },
        );
    }

    let mut bc = BuildCollect {
        tasks,
        idx: 0,
        out: HashMap::new(),
    };
    let mut sink2 = Module::new();
    bc.parse_core_module(&mut sink2, Parser::new(0), bytes)
        .map_err(|e| anyhow!("merge build failed: {e}"))?;

    // Decide profitability with a provisional merged index, then rebuild
    // wrappers with final indices for the selected groups.
    let mut wrapper_pushes: Vec<Vec<Vec<Push>>> = Vec::new();
    let mut profitable: Vec<usize> = Vec::new();
    for (ci, c) in cands.iter().enumerate() {
        let Some(Some(body)) = bc.out.get(&c.rep) else {
            wrapper_pushes.push(Vec::new());
            continue;
        };
        let provisional = base_fn + ci as u32;
        let pushes = group_pushes(&groups[c.gid], &infos, &c.diff);
        let p = infos[c.rep].params as u32;
        let mut after = body.len() as i64;
        for push in &pushes {
            after += build_wrapper(p, push, provisional).len() as i64;
        }
        let before: i64 = groups[c.gid]
            .iter()
            .map(|&m| infos[m].raw_len as i64)
            .sum();
        if after + 32 < before {
            profitable.push(ci);
        }
        wrapper_pushes.push(pushes);
    }
    if profitable.is_empty() {
        return Ok(None);
    }

    let mut wrappers: Vec<Option<Vec<u8>>> = vec![None; n_def];
    let mut merged = Vec::new();
    for &ci in &profitable {
        let c = &cands[ci];
        let Some(Some(body)) = bc.out.get(&c.rep) else {
            continue;
        };
        let info = &infos[c.rep];
        let Some(ft) = a.func_types.get(info.ty as usize).and_then(|t| t.as_ref()) else {
            continue;
        };
        let mut params: Vec<ValType> = Vec::new();
        let mut ok = true;
        for p in &ft.params {
            match to_enc(*p) {
                Some(v) => params.push(v),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        let mut results: Vec<ValType> = Vec::new();
        for r in &ft.results {
            match to_enc(*r) {
                Some(v) => results.push(v),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        for &ord in &c.diff {
            match info.slots[ord] {
                Slot::Const(cv) => params.push(cv.kind().val_type()),
                Slot::Call(_) => params.push(ValType::I32),
            }
        }
        let merged_index = base_fn + merged.len() as u32;
        let pushes = &wrapper_pushes[ci];
        let p = info.params as u32;
        for (mi, &m) in groups[c.gid].iter().enumerate() {
            wrappers[m] = Some(build_wrapper(p, &pushes[mi], merged_index));
        }
        merged.push(MergedFn {
            params,
            results,
            body: body.clone(),
        });
    }

    if merged.is_empty() {
        return Ok(None);
    }
    Ok(Some(MergePlan {
        wrappers,
        merged,
        orig_type_count: base_ty,
    }))
}

fn call_slots_ok(
    members: &[usize],
    infos: &[FnInfo],
    diff: &[usize],
    a: &Analysis,
) -> bool {
    for &ord in diff {
        if let Slot::Call(_) = infos[members[0]].slots[ord] {
            let targets = call_targets(members, infos, ord);
            let mut sig: Option<(Vec<PValType>, Vec<PValType>)> = None;
            for &t in &targets {
                let Some(s) = defined_sig(a, t) else {
                    return false;
                };
                if s.1.len() > 1 {
                    return false;
                }
                if to_enc(s.1.first().copied().unwrap_or(PValType::I32)).is_none() {
                    return false;
                }
                if s.0.iter().any(|p| to_enc(*p).is_none()) {
                    return false;
                }
                match &sig {
                    None => sig = Some(s),
                    Some(prev) if *prev != s => return false,
                    _ => {}
                }
            }
            if sig.is_none() {
                return false;
            }
        }
    }
    true
}

fn call_targets(members: &[usize], infos: &[FnInfo], ord: usize) -> Vec<u32> {
    let mut v: Vec<u32> = members
        .iter()
        .filter_map(|&m| match infos[m].slots.get(ord) {
            Some(Slot::Call(t)) => Some(*t),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn diff_slots(members: &[usize], infos: &[FnInfo]) -> Vec<usize> {
    let rep = members[0];
    let n = infos[rep].slots.len();
    (0..n)
        .filter(|&o| {
            members
                .iter()
                .any(|&m| infos[m].slots.get(o).copied() != Some(infos[rep].slots[o]))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum Push {
    Const(ConstVal),
    Sel(i32),
}

fn group_pushes(members: &[usize], infos: &[FnInfo], diff: &[usize]) -> Vec<Vec<Push>> {
    members
        .iter()
        .map(|&m| {
            diff.iter()
                .map(|&ord| match infos[m].slots[ord] {
                    Slot::Const(c) => Push::Const(c),
                    Slot::Call(t) => {
                        let targets = call_targets(members, infos, ord);
                        let pos = targets.iter().position(|&x| x == t).unwrap_or(0);
                        Push::Sel(pos as i32)
                    }
                })
                .collect()
        })
        .collect()
}

fn build_wrapper(p: u32, pushes: &[Push], merged_index: u32) -> Vec<u8> {
    let mut f = Function::new(Vec::<(u32, ValType)>::new());
    for i in 0..p {
        f.instruction(&Instruction::LocalGet(i));
    }
    for push in pushes {
        match push {
            Push::Const(c) => {
                f.instruction(&const_of(*c));
            }
            Push::Sel(v) => {
                f.instruction(&Instruction::I32Const(*v));
            }
        }
    }
    f.instruction(&Instruction::Call(merged_index));
    f.instruction(&Instruction::End);
    f.into_raw_body()
}

fn const_of(c: ConstVal) -> Instruction<'static> {
    match c {
        ConstVal::I32(v) => Instruction::I32Const(v),
        ConstVal::I64(v) => Instruction::I64Const(v),
        ConstVal::F32(bits) => Instruction::F32Const(Ieee32::new(bits)),
        ConstVal::F64(bits) => Instruction::F64Const(Ieee64::new(bits)),
    }
}
