use wasm_encoder::Instruction;

/// Peephole-optimize a straight-line instruction stream.
///
/// Every rewrite is stack-balanced and non-trapping, so behavior is preserved:
/// - `nop` removal
/// - `const; drop` / `local.get; drop` removal
/// - `local.get n; local.set n` removal (identity)
/// - `local.get n; local.tee n` → `local.get n`
/// - `const a; const b; <non-trapping binop>` → `const (a op b)`
/// - `const c; eqz` → `const (c == 0)`
/// - right-identity pairs `x op c` → `x` when `c` is the identity for `op`
pub fn optimize(instrs: &mut Vec<Instruction<'_>>) {
    for _ in 0..8 {
        if !pass(instrs) {
            break;
        }
    }
}

fn is_const(i: &Instruction<'_>) -> bool {
    matches!(
        i,
        Instruction::I32Const(_)
            | Instruction::I64Const(_)
            | Instruction::F32Const(_)
            | Instruction::F64Const(_)
    )
}

fn pass(instrs: &mut Vec<Instruction<'_>>) -> bool {
    let mut out: Vec<Instruction<'_>> = Vec::with_capacity(instrs.len());
    let mut changed = false;
    let mut i = 0;
    while i < instrs.len() {
        if matches!(instrs[i], Instruction::Nop) {
            changed = true;
            i += 1;
            continue;
        }

        if i + 1 < instrs.len() {
            // const; drop  /  local.get; drop
            if (is_const(&instrs[i]) || matches!(instrs[i], Instruction::LocalGet(_)))
                && matches!(instrs[i + 1], Instruction::Drop)
            {
                changed = true;
                i += 2;
                continue;
            }
            // local.get n; local.set n
            if let (Instruction::LocalGet(a), Instruction::LocalSet(b)) =
                (&instrs[i], &instrs[i + 1])
                && a == b
            {
                changed = true;
                i += 2;
                continue;
            }
            // local.get n; local.tee n → local.get n
            if let (Instruction::LocalGet(a), Instruction::LocalTee(b)) =
                (&instrs[i], &instrs[i + 1])
                && a == b
            {
                out.push(instrs[i].clone());
                changed = true;
                i += 2;
                continue;
            }
            // local.tee n; drop → local.set n
            if let (Instruction::LocalTee(a), Instruction::Drop) = (&instrs[i], &instrs[i + 1]) {
                out.push(Instruction::LocalSet(*a));
                changed = true;
                i += 2;
                continue;
            }
            // const c; eqz → const (c == 0)
            if let Some(folded) = fold_const_eqz(&instrs[i], &instrs[i + 1]) {
                out.push(folded);
                changed = true;
                i += 2;
                continue;
            }
            // x; const 0; eq → x; eqz
            if is_zero_eq_to_eqz(&instrs[i], &instrs[i + 1]) {
                out.push(eqz_of(&instrs[i]));
                changed = true;
                i += 2;
                continue;
            }
            // x op c → x when c is a right-identity for op
            if strip_right_identity(&instrs[i], &instrs[i + 1]) {
                changed = true;
                i += 2;
                continue;
            }
        }

        if i + 2 < instrs.len()
            && let Some(folded) = fold_const_binop(&instrs[i], &instrs[i + 1], &instrs[i + 2])
        {
            out.push(folded);
            changed = true;
            i += 3;
            continue;
        }

        out.push(instrs[i].clone());
        i += 1;
    }
    *instrs = out;
    changed
}

fn fold_const_eqz(a: &Instruction<'_>, b: &Instruction<'_>) -> Option<Instruction<'static>> {
    match (a, b) {
        (Instruction::I32Const(v), Instruction::I32Eqz) => {
            Some(Instruction::I32Const(i32::from(*v == 0)))
        }
        (Instruction::I64Const(v), Instruction::I64Eqz) => {
            Some(Instruction::I32Const(i32::from(*v == 0)))
        }
        _ => None,
    }
}

/// `const 0; eq` → `eqz` (same result, drops the const).
fn is_zero_eq_to_eqz(a: &Instruction<'_>, b: &Instruction<'_>) -> bool {
    matches!(
        (a, b),
        (Instruction::I32Const(0), Instruction::I32Eq)
            | (Instruction::I64Const(0), Instruction::I64Eq)
    )
}

fn eqz_of(a: &Instruction<'_>) -> Instruction<'static> {
    match a {
        Instruction::I32Const(_) => Instruction::I32Eqz,
        Instruction::I64Const(_) => Instruction::I64Eqz,
        _ => unreachable!("eqz_of only for zero consts"),
    }
}

/// `const a; const b; binop` → `const (a op b)`.
/// `a` is pushed first, so it is the left operand.
fn fold_const_binop(
    a: &Instruction<'_>,
    b: &Instruction<'_>,
    op: &Instruction<'_>,
) -> Option<Instruction<'static>> {
    match (a, b, op) {
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Add) => {
            Some(Instruction::I32Const(x.wrapping_add(*y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Sub) => {
            Some(Instruction::I32Const(x.wrapping_sub(*y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Mul) => {
            Some(Instruction::I32Const(x.wrapping_mul(*y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32And) => {
            Some(Instruction::I32Const(x & y))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Or) => {
            Some(Instruction::I32Const(x | y))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Xor) => {
            Some(Instruction::I32Const(x ^ y))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Shl) => {
            Some(Instruction::I32Const(x.wrapping_shl(*y as u32)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32ShrS) => {
            Some(Instruction::I32Const(x.wrapping_shr(*y as u32)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32ShrU) => {
            Some(Instruction::I32Const(
                ((*x as u32).wrapping_shr(*y as u32)) as i32,
            ))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Rotl) => {
            Some(Instruction::I32Const(x.rotate_left(*y as u32)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Rotr) => {
            Some(Instruction::I32Const(x.rotate_right(*y as u32)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Eq) => {
            Some(Instruction::I32Const(i32::from(x == y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32Ne) => {
            Some(Instruction::I32Const(i32::from(x != y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32LtS) => {
            Some(Instruction::I32Const(i32::from(x < y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32LtU) => {
            Some(Instruction::I32Const(i32::from((*x as u32) < (*y as u32))))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32GtS) => {
            Some(Instruction::I32Const(i32::from(x > y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32GtU) => {
            Some(Instruction::I32Const(i32::from((*x as u32) > (*y as u32))))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32LeS) => {
            Some(Instruction::I32Const(i32::from(x <= y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32LeU) => {
            Some(Instruction::I32Const(i32::from((*x as u32) <= (*y as u32))))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32GeS) => {
            Some(Instruction::I32Const(i32::from(x >= y)))
        }
        (Instruction::I32Const(x), Instruction::I32Const(y), Instruction::I32GeU) => {
            Some(Instruction::I32Const(i32::from((*x as u32) >= (*y as u32))))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Add) => {
            Some(Instruction::I64Const(x.wrapping_add(*y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Sub) => {
            Some(Instruction::I64Const(x.wrapping_sub(*y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Mul) => {
            Some(Instruction::I64Const(x.wrapping_mul(*y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64And) => {
            Some(Instruction::I64Const(x & y))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Or) => {
            Some(Instruction::I64Const(x | y))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Xor) => {
            Some(Instruction::I64Const(x ^ y))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Shl) => {
            Some(Instruction::I64Const(x.wrapping_shl(*y as u32)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64ShrS) => {
            Some(Instruction::I64Const(x.wrapping_shr(*y as u32)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64ShrU) => {
            Some(Instruction::I64Const(
                ((*x as u64).wrapping_shr(*y as u32)) as i64,
            ))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Eq) => {
            Some(Instruction::I32Const(i32::from(x == y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64Ne) => {
            Some(Instruction::I32Const(i32::from(x != y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64LtS) => {
            Some(Instruction::I32Const(i32::from(x < y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64LtU) => {
            Some(Instruction::I32Const(i32::from((*x as u64) < (*y as u64))))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64GtS) => {
            Some(Instruction::I32Const(i32::from(x > y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64GtU) => {
            Some(Instruction::I32Const(i32::from((*x as u64) > (*y as u64))))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64LeS) => {
            Some(Instruction::I32Const(i32::from(x <= y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64LeU) => {
            Some(Instruction::I32Const(i32::from((*x as u64) <= (*y as u64))))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64GeS) => {
            Some(Instruction::I32Const(i32::from(x >= y)))
        }
        (Instruction::I64Const(x), Instruction::I64Const(y), Instruction::I64GeU) => {
            Some(Instruction::I32Const(i32::from((*x as u64) >= (*y as u64))))
        }
        _ => None,
    }
}

/// `const c` immediately before a binary op (so `c` is the right operand):
/// drop both instructions when `x op c == x` for all `x`.
fn strip_right_identity(c: &Instruction<'_>, op: &Instruction<'_>) -> bool {
    matches!(
        (c, op),
        (Instruction::I32Const(0), Instruction::I32Add)
            | (Instruction::I32Const(0), Instruction::I32Or)
            | (Instruction::I32Const(0), Instruction::I32Xor)
            | (Instruction::I32Const(0), Instruction::I32Sub)
            | (Instruction::I32Const(0), Instruction::I32Shl)
            | (Instruction::I32Const(0), Instruction::I32ShrS)
            | (Instruction::I32Const(0), Instruction::I32ShrU)
            | (Instruction::I32Const(0), Instruction::I32Rotl)
            | (Instruction::I32Const(0), Instruction::I32Rotr)
            | (Instruction::I32Const(1), Instruction::I32Mul)
            | (Instruction::I32Const(-1), Instruction::I32And)
            | (Instruction::I64Const(0), Instruction::I64Add)
            | (Instruction::I64Const(0), Instruction::I64Or)
            | (Instruction::I64Const(0), Instruction::I64Xor)
            | (Instruction::I64Const(0), Instruction::I64Sub)
            | (Instruction::I64Const(0), Instruction::I64Shl)
            | (Instruction::I64Const(0), Instruction::I64ShrS)
            | (Instruction::I64Const(0), Instruction::I64ShrU)
            | (Instruction::I64Const(1), Instruction::I64Mul)
            | (Instruction::I64Const(-1), Instruction::I64And)
    )
}
