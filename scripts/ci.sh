#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly REPO_ROOT

cd -- "$REPO_ROOT"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

die() {
    printf 'ci: error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

required_toolchain() {
    sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
        rust-toolchain.toml
}

check_toolchain() {
    local required actual_rust actual_cargo
    required="$(required_toolchain)"
    [[ -n "$required" ]] || die "cannot read channel from rust-toolchain.toml"

    actual_rust="$(rustc --version | awk '{print $2}')"
    actual_cargo="$(cargo --version | awk '{print $2}')"
    [[ "$actual_rust" == "$required" ]] ||
        die "rustc $required is required (found $actual_rust)"
    [[ "$actual_cargo" == "$required" ]] ||
        die "cargo $required is required (found $actual_cargo)"
}

run_fmt() {
    cargo fmt --all -- --check
}

run_clippy() {
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy -p qaudit-hsm --features pkcs11 --all-targets --locked -- -D warnings
    cargo clippy -p qgateway --features pkcs11 --all-targets --locked -- -D warnings
}

run_test() {
    cargo test --workspace --locked --no-fail-fast
    cargo test --workspace --release --locked --no-fail-fast
}

run_pkcs11() {
    cargo test -p qaudit-hsm --features pkcs11 --locked
    cargo build --release -p qgateway --features pkcs11 --locked
}

run_build() {
    cargo build --release --workspace --locked
    cargo build --release -p qgateway --features pkcs11 --locked
}

run_audit() {
    command -v cargo-audit >/dev/null 2>&1 ||
        die "cargo-audit is required (CI pins cargo-audit 0.22.2)"
    cargo audit --deny warnings
}

usage() {
    cat <<'EOF'
Usage: scripts/ci.sh [all|fmt|clippy|test|pkcs11|build|audit]

Runs the same locked validation gates locally and in CI. The exact Rust and
Cargo version is read from rust-toolchain.toml and enforced before every gate.
EOF
}

main() {
    local gate="${1:-all}"

    [[ $# -le 1 ]] || {
        usage >&2
        exit 2
    }

    case "$gate" in
        -h | --help | help)
            usage
            return 0
            ;;
    esac

    require_command cargo
    require_command rustc
    check_toolchain

    case "$gate" in
        all)
            run_fmt
            run_clippy
            run_test
            run_pkcs11
            run_build
            run_audit
            ;;
        fmt) run_fmt ;;
        clippy) run_clippy ;;
        test) run_test ;;
        pkcs11) run_pkcs11 ;;
        build) run_build ;;
        audit) run_audit ;;
        *)
            usage >&2
            die "unknown gate: $gate"
            ;;
    esac
}

main "$@"
