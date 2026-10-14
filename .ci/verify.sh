#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path.txt}"
touch "$GITHUB_PATH"

bash .ci/update-our-crates.sh
cargo metadata --locked --format-version 1 > dependency-metadata.json
python3 .github/check-first-party.py
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo fmt --all
git diff -- '*.rs' > rustfmt.patch
test ! -s rustfmt.patch
python3 .github/test-check-source-coverage.py

rustc --version
cargo fmt --all --check
python3 scripts/check-fixtures.py
cargo clippy --locked --all-targets --features http -- -D warnings
cargo test --locked --features http
cargo check --locked --target wasm32-unknown-unknown
bash scripts/wasm-runner.sh
# shellcheck disable=SC1090
if [ -f "$GITHUB_PATH" ]; then while IFS= read -r p; do [ -n "$p" ] && PATH="$p:$PATH"; done < "$GITHUB_PATH"; fi
export PATH
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test --locked --target wasm32-unknown-unknown --test follower --test door

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --features http --ignore-filename-regex '(^|/)(tests|scripts)/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --text --show-instantiations > coverage.txt
)
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt

python3 .github/check-first-party.py
