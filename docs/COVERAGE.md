# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% covered production lines and branches, from the
LLVM JSON counts, and refuses absent or empty measurements. There are no
production-code exclusions. Test harness and fixture files are excluded because
they are validation inputs rather than shipped behavior. A failed gate is an
open test gap, never evidence of complete coverage.

Dependencies are resolved once per CI run and the resulting Cargo.lock artifact
is reused by every job. CI refreshes within the declared ranges;
Dependabot proposes lockfile updates for review and merging after full CI.
The checked-in lock and per-run artifacts retain exact reproducible resolutions.

## Branchless facade

After Envoy extraction, Assurance has 56 measured production lines and no
instrumentable branch sites (LLVM reports zero, with branch instrumentation
explicitly enabled). All 56 lines execute in the real integration tests. Only
this facade opts into `--branchless-facade`: a zero branch count is accepted only
when every file explicitly reports an empty branch list and every production
line remains covered. Any introduced branch must be 100% covered. No production
file is excluded and no synthetic branch is added to manufacture a denominator.
Charter, Guard and Envoy retain strict nonempty line/branch gates in their owners.

The source gate now requires complete LCOV, raw JSON and annotated text from the
same instrumented execution. Every source file, emitted line, branch and hit/miss
must agree. A single-file annotated report may omit its filename heading only
when the other two inventories identify exactly one source file. The exclusion
manifest is empty; source coverage does not claim every generic instantiation.
