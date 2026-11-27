#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$ROOT=."

build_wasm() {
  command -v wasm-pack >/dev/null 2>&1 || {
    echo "wasm-pack is required; install the pinned version from docs/deployment.md." >&2
    return 127
  }
  wasm-pack build crypto-wasm --target web --out-dir pkg --out-name crypto_wasm || return
  mkdir -p client-app/public/crypto-wasm || return
  install -m 0644 crypto-wasm/pkg/crypto_wasm.js client-app/public/crypto-wasm/crypto_wasm.js || return
  install -m 0644 crypto-wasm/pkg/crypto_wasm_bg.wasm client-app/public/crypto-wasm/crypto_wasm_bg.wasm
}

check_metadata() {
  cargo metadata --locked --format-version 1 --no-deps >/dev/null
}

run_application() {
  build_wasm || return
  npm --prefix client-app ci || return
  npm --prefix client-app run build || return
  if [[ "${USTOY_TOR:-0}" == "1" ]]; then
    docker compose -f docker-compose.prod.yml --profile tor up --build -d
  else
    docker compose -f docker-compose.prod.yml up --build -d
  fi
}

verify_all() {
  declare -A result
  local failures=0

  run_step() {
    local name="$1"
    shift
    printf '\n== %s ==\n' "$name"
    if "$@"; then
      result["$name"]="PASS"
    else
      result["$name"]="FAIL ($?)"
      failures=$((failures + 1))
    fi
  }

  run_step "Formatting" cargo fmt --all -- --check
  run_step "Cargo metadata" check_metadata
  run_step "Clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
  run_step "Rust tests" cargo test --workspace --locked
  run_step "Wasm build" build_wasm
  run_step "npm ci" npm --prefix client-app ci
  run_step "UI tests" npm --prefix client-app test
  run_step "UI build" npm --prefix client-app run build

  local core_a="" relay_a="" core_b="" relay_b=""
  cargo clean --target-dir target/ustoy-repro-a >/dev/null 2>&1 || true
  if cargo build --release --locked --target-dir target/ustoy-repro-a \
    -p veyl-crypto-core -p veyl-relay-server; then
    core_a="$(find target/ustoy-repro-a/release/deps -maxdepth 1 -type f -name 'libveyl_crypto_core-*.rlib' -print -quit)"
    if [[ -n "$core_a" ]]; then
      core_a="$(sha256sum "$core_a" | cut -d' ' -f1)"
      relay_a="$(sha256sum target/ustoy-repro-a/release/veyl-relay-server | cut -d' ' -f1)"
      result["Release build A"]="PASS"
    else
      result["Release build A"]="FAIL (crypto-core artifact missing)"
      failures=$((failures + 1))
    fi
  else
    result["Release build A"]="FAIL"
    failures=$((failures + 1))
  fi

  cargo clean --target-dir target/ustoy-repro-b >/dev/null 2>&1 || true
  if cargo build --release --locked --target-dir target/ustoy-repro-b \
    -p veyl-crypto-core -p veyl-relay-server; then
    core_b="$(find target/ustoy-repro-b/release/deps -maxdepth 1 -type f -name 'libveyl_crypto_core-*.rlib' -print -quit)"
    if [[ -n "$core_b" ]]; then
      core_b="$(sha256sum "$core_b" | cut -d' ' -f1)"
      relay_b="$(sha256sum target/ustoy-repro-b/release/veyl-relay-server | cut -d' ' -f1)"
      result["Release build B"]="PASS"
    else
      result["Release build B"]="FAIL (crypto-core artifact missing)"
      failures=$((failures + 1))
    fi
  else
    result["Release build B"]="FAIL"
    failures=$((failures + 1))
  fi

  if [[ -n "$core_a" && -n "$core_b" && -n "$relay_a" && -n "$relay_b" ]]; then
    if [[ "$core_a" == "$core_b" && "$relay_a" == "$relay_b" ]]; then
      result["SHA-256 reproducibility"]="PASS"
    else
      result["SHA-256 reproducibility"]="FAIL"
      failures=$((failures + 1))
    fi
  else
    result["SHA-256 reproducibility"]="NOT RUN"
    failures=$((failures + 1))
  fi

  printf '\nUstoy local verification report\n'
  for name in "Formatting" "Cargo metadata" "Clippy" "Rust tests" "Wasm build" "npm ci" "UI tests" "UI build" "Release build A" "Release build B" "SHA-256 reproducibility"; do
    printf '  %-27s %s\n' "$name" "${result[$name]:-NOT RUN}"
  done
  if [[ -n "$core_a" && -n "$core_b" ]]; then
    printf '  crypto-core SHA-256       %s / %s\n' "$core_a" "$core_b"
    printf '  relay-server SHA-256      %s / %s\n' "$relay_a" "$relay_b"
  else
    printf '  release SHA-256           unavailable\n'
  fi
  return "$((failures > 0))"
}

case "${1:-}" in
  build-wasm) build_wasm ;;
  verify) verify_all ;;
  run) run_application ;;
  *)
    echo "Usage: $0 {build-wasm|verify|run}" >&2
    exit 2
    ;;
esac
