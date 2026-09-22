# wasm-trim

Post-link WebAssembly size optimizer with runtime-specific profiles. It
re-encodes an existing `.wasm` binary, applying a staged pipeline of
behavior-preserving passes, and reports raw and gzip size deltas along with
checks that the module's interface and behavior-relevant structure are intact.

First-class support for **.NET** WASM output (Mono interpreter and NativeAOT),
with automatic runtime detection and section handling.

## Results

Measured on real `dotnet new blazor` apps published with the .NET 10 SDK
(raw / gzip). Exact numbers depend on the app and toolchain.

| Fixture | Raw | Gzip |
|---|---|---|
| Blazor **NativeAOT** (11.86 MB) | 11.86 MB → **9.98 MB (−15.9%)** | 3.84 MB → 3.60 MB (−6.4%) |
| Blazor **NativeAOT**, larger app (19.27 MB, 76.5k functions) | 19.27 MB → **15.84 MB (−17.8%)** | 5.96 MB → 5.60 MB (−6.0%) |
| Blazor **Mono** runtime (2.86 MB) | 2.86 MB → 2.85 MB (−0.5%) | roughly flat |

Mono gains are small because that module is almost entirely the shared runtime
with no duplicated application code; NativeAOT bakes the app into the module and
has far more redundancy to remove.

## Install

```sh
cargo install --path .                              # from a clone
cargo install --git https://github.com/stackmator/wasm-trim
```

Installs `wasm-trim` into `~/.cargo/bin`. Requires Rust 1.87 or newer.

Or build locally:

```sh
cargo build --release
# binary at target/release/wasm-trim(.exe)
```

## Usage

```sh
# Inspect a module without modifying it
wasm-trim analyze app.wasm
wasm-trim app.wasm              # shorthand for the above

# Optimize; never overwrites the input
wasm-trim optimize app.wasm -o app.opt.wasm

# Compare two modules (interface, sections, sizes)
wasm-trim diff app.wasm app.opt.wasm
```

`optimize` refuses to run if `-o` points at the input file.

### Options

| Flag | Effect |
|---|---|
| `-o, --output <FILE>` | Output path (required) |
| `--profile <auto\|dotnet\|none>` | Runtime profile used for detection and section policy (default `auto`) |
| `--strip-custom <NAME>` | Also strip a custom section; use `all` for every unprotected one |
| `--keep-custom <NAME>` | Never strip the named custom section |
| `--no-strip` | Disable custom-section stripping |
| `--no-data` | Disable data-segment optimization |
| `--no-code` | Disable instruction-level peephole optimization |
| `--no-dedupe` | Disable duplicate-function folding |
| `--no-dce` | Disable dead-code elimination |
| `--no-merge` | Disable near-duplicate function merging |

## Pipeline

Each stage re-analyzes the current module, re-encodes it, and validates the
result before the next stage runs:

1. **Section stripping** — removes debug/tooling custom sections (`name`,
   `producers`, `sourceMappingURL`, `sourceMap`). Runtime-critical sections
   (`target_features`, `dylink`, `dylink.0`, `linking`, `reloc.*`) and the
   profile section (`dotnet`) are protected. The `name` section is force-stripped
   whenever indices change.
2. **Data optimization** — removes unreferenced passive segments, folds
   byte-identical active segments, and elides all-zero active segments that
   overlap no non-zero segment (safe because memory starts zeroed).
3. **Code optimization** — instruction peephole: `nop` removal, `const; const;
   binop` folding, right-identity stripping, `const; eqz`/`const 0; eq`
   folding, and `local.get`/`local.set`/`local.tee` simplifications. Runs before
   folding so normalized bodies create more fold groups.
4. **Function folding** — merges defined functions with byte-identical bodies
   and the same type.
5. **Dead code elimination** — reachability from exports, the start function,
   element segments and global initializers, following `call`/`return_call`/
   `ref.func` edges.
6. **Function merging** — groups whole bodies that are structurally identical
   except for parameterizable *slots*:
   - differing **constants** become value parameters;
   - differing **call targets** become an `i32` selector parameter with an
     argument-spilling `if`/`else` dispatch chain (no `call_ref`, no extra
     tables, no non-default proposals).

   One shared body is appended and the originals become thin wrappers. Each
   merge is gated on exact encoded size and must save at least 32 bytes, so a
   merge can never make the output larger.

## Behavior-preserving checks

Every `optimize` run reports:

- **WASM validation** — input and output validate.
- **Import compatibility** — import list is preserved.
- **Export compatibility** — exports preserved and remapped through the index
  permutation.
- **Start function compatibility** — start section remapped or preserved.
- **Section integrity** — same set of non-custom sections.
- **Deterministic output** — the whole pipeline is run twice and must produce
  byte-identical output.

All stages are validated with `wasmparser`; `optimize` aborts if any check fails.

## Runtime detection

Profiles are detected from imports/exports:

- `.NET NativeAOT` — one or more `mono_aot_<Assembly>_get_method` exports.
  (AOT output also links the interpreter runtime, so `mono_interp_*` imports
  alone do not indicate interpreted output.)
- `.NET Mono` — `mono_interp_*` imports without AOT exports.
- `.NET` — `mono_*` imports or a `dotnet` custom section.
- Also recognizes `rust`, `go`, `emscripten`, and `wasi` markers.

## Development

```sh
cargo test --release      # integration + unit tests
cargo clippy --all-targets --release
```

Tests that need a large `.wasm` fixture skip automatically when it is absent.
Fixtures are not committed (they are large and regenerated); `.gitignore`
excludes `testdata/fixtures/*.wasm`.

- `testdata/build-fixtures.ps1` rebuilds the Mono and NativeAOT fixtures from the
  small template projects (requires the .NET 10 SDK and
  `dotnet workload install wasm-tools`).
- `optimize_large_aot_fixture` is `#[ignore]`d by default. To use it, publish a
  large standalone Blazor WASM app with `-p:RunAOTCompilation=true` and copy its
  `wwwroot/_framework/dotnet.native*.wasm` to
  `testdata/fixtures/dotnet.native.large.aot.wasm`, then run
  `cargo test --release -- --ignored`.

## Limitations

- Component-model modules are not supported.
- Function merging only parameterizes integer/float constants and direct
  `call` targets; other differing immediates (globals, memory offsets,
  `call_indirect`, `ref.func`) prevent a group from being merged.
- The optimizer is intentionally conservative: it never applies a transformation
  it cannot re-validate and size-check.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

