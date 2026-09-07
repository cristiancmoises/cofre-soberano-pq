#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 0022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly REPO_ROOT
readonly REQUIRED_CARGO_CYCLONEDX_VERSION="0.5.9"
readonly REQUIRED_COSIGN_VERSION="3.1.3"
readonly ML_DSA_CONTEXT="cofre-soberano-pq-release-v1"

OUTPUT_DIR="$REPO_ROOT/dist"
RELEASE_TARGET=""
WORK_DIR=""
MODE="candidate"
MODE_SET="false"
COSIGN_TOOL_VERSION=""
OPENSSL_TOOL_VERSION=""
SOURCE_DIRTY="false"

die() {
    printf 'release: error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf 'release: %s\n' "$*" >&2
}

usage() {
    cat <<'EOF'
Usage: scripts/release.sh [--candidate|--release] [--output DIRECTORY] [--target RUST_TARGET]

Candidate mode is the default. It builds and verifies deterministic archives,
a CycloneDX SBOM, the JSON manifest, and SHA256SUMS. Its manifest is marked
publishable=false and may include uncommitted source changes.

Release mode additionally requires a clean worktree, an annotated v<version>
tag at HEAD, and both ML-DSA-87 and Cosign signing material. Its manifest is
marked publishable=true. The output directory must not already exist. Builds
are native Linux builds; run once in a clean builder for each supported target.

Additional environment required only by --release (values are never printed):
  ML_DSA_PRIVATE_KEY    OpenSSL 3.5+ ML-DSA-87 private key in PEM format
  ML_DSA_PUBLIC_KEY     matching ML-DSA-87 public key in PEM format
  SIGSTORE_PRIVATE_KEY  Cosign private key path or supported KMS URI
  SIGSTORE_PUBLIC_KEY   matching Cosign public key path
  COSIGN_PASSWORD       when the Cosign private key is password-protected

Required tools in both modes:
  Rust/Cargo from rust-toolchain.toml, GNU tar, gzip, Python 3,
  and cargo-cyclonedx 0.5.9. Release mode also requires Cosign 3.1.3
  and OpenSSL 3.5 or newer. This script never creates signing keys.
EOF
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        case "$WORK_DIR" in
            */.cofre-release-work.*) rm -rf -- "$WORK_DIR" ;;
            *) printf 'release: refusing to clean unexpected path: %s\n' "$WORK_DIR" >&2 ;;
        esac
    fi
}

trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_file() {
    [[ -f "$1" && -r "$1" ]] || die "$2 is not a readable file"
}

required_toolchain() {
    sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
        "$REPO_ROOT/rust-toolchain.toml"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --candidate | --release)
                [[ "$MODE_SET" == "false" ]] || die "choose only one release mode"
                MODE="${1#--}"
                MODE_SET="true"
                shift
                ;;
            --output)
                [[ $# -ge 2 ]] || die "--output requires a directory"
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --target)
                [[ $# -ge 2 ]] || die "--target requires a Rust target triple"
                RELEASE_TARGET="$2"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *) die "unknown argument: $1" ;;
        esac
    done
}

check_prerequisites() {
    local command_name
    for command_name in \
        awk cargo cargo-cyclonedx cmp find git grep gzip install python3 \
        realpath rustc sed sha256sum stat tar; do
        require_command "$command_name"
    done

    [[ "$(uname -s)" == "Linux" ]] || die "release bundles must be built on Linux"

    local required_rust actual_rust actual_cargo host_target
    required_rust="$(required_toolchain)"
    [[ -n "$required_rust" ]] || die "cannot read channel from rust-toolchain.toml"
    actual_rust="$(rustc --version | awk '{print $2}')"
    actual_cargo="$(cargo --version | awk '{print $2}')"
    [[ "$actual_rust" == "$required_rust" ]] ||
        die "rustc $required_rust is required (found $actual_rust)"
    [[ "$actual_cargo" == "$required_rust" ]] ||
        die "cargo $required_rust is required (found $actual_cargo)"

    host_target="$(rustc -vV | sed -n 's/^host: //p')"
    [[ -n "$host_target" ]] || die "cannot determine the rustc host target"
    RELEASE_TARGET="${RELEASE_TARGET:-$host_target}"
    [[ "$RELEASE_TARGET" == "$host_target" ]] ||
        die "cross-packaging is not supported; build natively on $RELEASE_TARGET"

    local cyclonedx_version
    cyclonedx_version="$(cargo cyclonedx --version 2>/dev/null | awk '{print $NF}')"
    [[ "$cyclonedx_version" == "$REQUIRED_CARGO_CYCLONEDX_VERSION" ]] ||
        die "cargo-cyclonedx $REQUIRED_CARGO_CYCLONEDX_VERSION is required (found ${cyclonedx_version:-unknown})"
}

check_signing_prerequisites() {
    require_command cosign
    require_command openssl

    COSIGN_TOOL_VERSION="$(cosign version 2>/dev/null | sed -nE 's/^[[:space:]]*GitVersion:[[:space:]]*v?([^[:space:]]+).*/\1/p' | head -n1)"
    [[ "$COSIGN_TOOL_VERSION" == "$REQUIRED_COSIGN_VERSION" ]] ||
        die "Cosign $REQUIRED_COSIGN_VERSION is required (found ${COSIGN_TOOL_VERSION:-unknown})"

    OPENSSL_TOOL_VERSION="$(openssl version | awk '{print $2}')"
    [[ "$(printf '%s\n%s\n' "3.5.0" "$OPENSSL_TOOL_VERSION" | sort -V | head -n1)" == "3.5.0" ]] ||
        die "OpenSSL 3.5 or newer with ML-DSA support is required"
    openssl list -signature-algorithms 2>/dev/null | grep -Eqi 'ML-DSA-87' ||
        die "OpenSSL does not expose the ML-DSA-87 signature algorithm"

    : "${ML_DSA_PRIVATE_KEY:?release: ML_DSA_PRIVATE_KEY is required}"
    : "${ML_DSA_PUBLIC_KEY:?release: ML_DSA_PUBLIC_KEY is required}"
    : "${SIGSTORE_PRIVATE_KEY:?release: SIGSTORE_PRIVATE_KEY is required}"
    : "${SIGSTORE_PUBLIC_KEY:?release: SIGSTORE_PUBLIC_KEY is required}"
    require_file "$ML_DSA_PRIVATE_KEY" "ML_DSA_PRIVATE_KEY"
    require_file "$ML_DSA_PUBLIC_KEY" "ML_DSA_PUBLIC_KEY"
    if [[ "$SIGSTORE_PRIVATE_KEY" != *"://"* && "$SIGSTORE_PRIVATE_KEY" != pkcs11:* ]]; then
        require_file "$SIGSTORE_PRIVATE_KEY" "SIGSTORE_PRIVATE_KEY"
    fi
    require_file "$SIGSTORE_PUBLIC_KEY" "SIGSTORE_PUBLIC_KEY"
}

workspace_version() {
    cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json, sys
metadata = json.load(sys.stdin)
members = set(metadata["workspace_members"])
versions = {p["version"] for p in metadata["packages"] if p["id"] in members}
if len(versions) != 1:
    raise SystemExit("workspace packages do not share exactly one version")
print(versions.pop())
'
}

check_build_state() {
    local version="$1" tag="$2" commit="$3"
    if [[ "$MODE" == "release" ]]; then
        [[ -z "$(git status --porcelain=v1 --untracked-files=normal)" ]] ||
            die "release mode requires a clean Git worktree"
        [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null || true)" == "tag" ]] ||
            die "$tag must exist as an annotated tag"
        [[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$commit" ]] ||
            die "$tag does not point to HEAD ($commit)"
    fi

    local output_real repo_real
    output_real="$(realpath -m -- "$OUTPUT_DIR")"
    repo_real="$(realpath -m -- "$REPO_ROOT")"
    case "$output_real" in
        / | "$repo_real" | "$repo_real/.git" | "$repo_real/.git"/*)
            die "unsafe output directory: $output_real"
            ;;
    esac
    [[ ! -e "$output_real" ]] || die "output path already exists: $output_real"
    OUTPUT_DIR="$output_real"

    if [[ "$MODE" == "release" ]]; then
        note "validated release $tag at $commit for target $RELEASE_TARGET"
    else
        note "validated non-publishable candidate at $commit for target $RELEASE_TARGET"
    fi
}

check_binary_version() {
    local binary="$1" expected="$2" actual
    [[ -x "$binary" ]] || die "missing executable: $binary"
    actual="$($binary --version | awk '{print $NF}')"
    [[ "$actual" == "$expected" ]] ||
        die "$(basename -- "$binary") reports $actual, expected $expected"
}

copy_release_files() {
    local bundle_root="$1"

    install -d -m 0755 \
        "$bundle_root/bin" "$bundle_root/docs" "$bundle_root/systemd" \
        "$bundle_root/screenshots" "$bundle_root/release-keys"
    install -m 0644 \
        "$REPO_ROOT/README.md" \
        "$REPO_ROOT/README.pt-BR.md" \
        "$REPO_ROOT/CHANGELOG.md" \
        "$REPO_ROOT/CHANGELOG.pt-BR.md" \
        "$REPO_ROOT/SPEC.md" \
        "$REPO_ROOT/NOTICE" \
        "$REPO_ROOT/LICENSE-AGPL" \
        "$REPO_ROOT/LICENSE-COMMERCIAL" \
        "$bundle_root/"
    install -m 0644 \
        "$REPO_ROOT/docs/RUNBOOK.md" \
        "$REPO_ROOT/docs/RUNBOOK.pt-BR.md" \
        "$REPO_ROOT/docs/HSM.md" \
        "$REPO_ROOT/docs/HSM.pt-BR.md" \
        "$REPO_ROOT/docs/SMOKE_TEST.md" \
        "$REPO_ROOT/docs/SMOKE_TEST.pt-BR.md" \
        "$bundle_root/docs/"
    install -m 0644 "$REPO_ROOT/systemd/qgateway.service" "$bundle_root/systemd/"
    install -m 0644 "$REPO_ROOT"/screenshots/*.png "$bundle_root/screenshots/"
    install -m 0644 "$REPO_ROOT"/release-keys/*.pem "$bundle_root/release-keys/"
}

make_archive() {
    local parent="$1" root_name="$2" destination="$3" epoch="$4"
    TZ=UTC tar \
        --sort=name \
        --mtime="@$epoch" \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        --format=gnu \
        -C "$parent" \
        -cf - \
        "$root_name" | gzip -n -9 >"$destination"
}

scan_for_private_material() {
    local path="$1"
    local scan_status=0
    if grep -RIEq \
        '(github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)' \
        "$path"; then
        die "possible credential or private key found in staged release content"
    else
        scan_status=$?
    fi
    [[ "$scan_status" == "1" ]] || die "credential scanner could not inspect all staged content"
}

check_release_unchanged() {
    local tag="$1" commit="$2"
    [[ "$MODE" == "release" ]] || return 0
    [[ "$(git rev-parse HEAD)" == "$commit" ]] || die "HEAD changed during release build"
    [[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$commit" ]] ||
        die "release tag changed during build"
    [[ -z "$(git status --porcelain=v1 --untracked-files=normal)" ]] ||
        die "worktree changed during build; refusing to sign mismatched artifacts"
}

stage_source() {
    local source_parent="$1" source_name="$2" commit="$3"
    if [[ "$MODE" == "release" ]]; then
        git archive --format=tar --prefix="$source_name/" "$commit" |
            tar -xf - -C "$source_parent"
    else
        install -d -m 0755 "$source_parent/$source_name"
        (
            cd -- "$REPO_ROOT"
            git ls-files --cached --others --exclude-standard -z |
                tar --null --files-from=- -cf -
        ) | tar -xf - -C "$source_parent/$source_name"
    fi
}

merge_component_sboms() {
    local source_root="$1" sbom="$2" version="$3"
    python3 - "$source_root" "$sbom" "$version" <<'PY'
import json
import pathlib
import sys

source_root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
version = sys.argv[3]
paths = sorted(source_root.rglob(".cofre-component.cdx.json"))
if not paths:
    raise SystemExit("cargo-cyclonedx produced no component SBOMs")

# Cargo package IDs contain absolute staging paths, including mktemp's random
# directory. Map every workspace identity before traversing any document so
# references from siblings and nested binary/library targets normalize too.
boms = []
workspace_ids = {}
for path in paths:
    bom = json.loads(path.read_text(encoding="utf-8"))
    if bom.get("bomFormat") != "CycloneDX":
        raise SystemExit(f"invalid CycloneDX document: {path}")
    root = bom.get("metadata", {}).get("component")
    if not root or not all(root.get(key) for key in ("bom-ref", "name", "version")):
        raise SystemExit(f"component SBOM has no root identity: {path}")
    workspace_ids[root["bom-ref"]] = (
        f"urn:cofre-soberano-pq:workspace:{root['name']}:{root['version']}"
    )
    boms.append(bom)


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        for original, stable in workspace_ids.items():
            if value == original or value.startswith(original + " bin-target-"):
                return stable + value[len(original):]
    return value


components = {}
dependencies = {}
workspace_roots = {}
first = None
for bom in map(normalize, boms):
    first = first or bom
    root = bom["metadata"]["component"]
    workspace_roots[root["bom-ref"]] = root
    for component in [root, *bom.get("components", [])]:
        ref = component.get("bom-ref")
        if ref:
            components.setdefault(ref, component)
    for dependency in bom.get("dependencies", []):
        ref = dependency.get("ref")
        if ref:
            dependencies.setdefault(ref, set()).update(dependency.get("dependsOn", []))

# A dependency entry can precede its own workspace BOM. Keep that package's
# richer root metadata, including its nested binary/library target components.
components.update(workspace_roots)
workspace_refs = sorted(workspace_roots)

root_ref = f"pkg:cargo/cofre-soberano-pq@{version}"
metadata = dict(first.get("metadata", {}))
metadata["component"] = {
    "bom-ref": root_ref,
    "type": "application",
    "name": "cofre-soberano-pq",
    "version": version,
}
dependencies.setdefault(root_ref, set()).update(workspace_refs)
document = {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": first.get("specVersion", "1.5"),
    "version": 1,
    "metadata": metadata,
    "components": [components[key] for key in sorted(components)],
    "dependencies": [
        {"ref": key, "dependsOn": sorted(dependencies[key])}
        for key in sorted(dependencies)
    ],
}
if len(workspace_refs) < 7 or not document["components"]:
    raise SystemExit("aggregate SBOM is missing workspace components")
serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
if any(original in serialized for original in workspace_ids):
    raise SystemExit("aggregate SBOM still contains staging-dependent workspace references")
output.write_text(serialized, encoding="utf-8")
for path in paths:
    path.unlink()
PY
}

write_manifest() {
    local manifest="$1" version="$2" tag="$3" commit="$4" epoch="$5"
    local binary_archive="$6" source_archive="$7" sbom="$8"
    local dirty="$9"

    python3 - \
        "$manifest" "$version" "$tag" "$commit" "$epoch" "$RELEASE_TARGET" "$MODE" "$dirty" \
        "$binary_archive" "$source_archive" "$sbom" \
        "$(rustc --version)" "$(cargo --version)" \
        "$REQUIRED_CARGO_CYCLONEDX_VERSION" "$COSIGN_TOOL_VERSION" "$OPENSSL_TOOL_VERSION" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

(
    manifest_path, version, tag, commit, epoch, target, mode, dirty,
    binary_archive, source_archive, sbom,
    rustc_version, cargo_version, cyclonedx_version, cosign_version, openssl_version,
) = sys.argv[1:]

def artifact(path_string, kind, features):
    path = pathlib.Path(path_string)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "file": path.name,
        "kind": kind,
        "target": target if kind == "binary-bundle" else None,
        "features": features,
        "size": path.stat().st_size,
        "sha256": digest,
    }

created = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
document = {
    "schema_version": 1,
    "project": "cofre-soberano-pq",
    "version": version,
    "mode": mode,
    "publishable": mode == "release",
    "dirty": dirty == "true",
    "tag": tag or None,
    "commit": commit,
    "source_date_epoch": int(epoch),
    "created": created.isoformat().replace("+00:00", "Z"),
    "target": target,
    "toolchain": {
        "rustc": rustc_version,
        "cargo": cargo_version,
        "cargo-cyclonedx": cyclonedx_version,
        "cosign": cosign_version or None,
        "openssl": openssl_version or None,
    },
    "build": {
        "profile": "release",
        "locked_dependencies": True,
        "source_date_epoch": int(epoch),
        "variants": {
            "standard": {"features": []},
            "qgateway-pkcs11": {"features": ["qgateway/pkcs11"]},
        },
    },
    "signing": {
        "ml_dsa_87": mode == "release",
        "sigstore": mode == "release",
    },
    "artifacts": [
        artifact(binary_archive, "binary-bundle", ["standard", "qgateway/pkcs11"]),
        artifact(source_archive, "source-archive", []),
        artifact(sbom, "cyclonedx-sbom", []),
    ],
}
pathlib.Path(manifest_path).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

ml_dsa_sign() {
    local payload="$1" signature="$2"
    openssl pkeyutl \
        -sign \
        -inkey "$ML_DSA_PRIVATE_KEY" \
        -in "$payload" \
        -out "$signature" \
        -pkeyopt "context-string:$ML_DSA_CONTEXT" >/dev/null
    [[ "$(stat -c '%s' "$signature")" == "4627" ]] ||
        die "ML-DSA signature has the wrong size; an ML-DSA-87 key is required"
}

ml_dsa_verify() {
    local payload="$1" signature="$2" public_key="$3"
    openssl pkeyutl \
        -verify \
        -pubin \
        -inkey "$public_key" \
        -in "$payload" \
        -sigfile "$signature" \
        -pkeyopt "context-string:$ML_DSA_CONTEXT" >/dev/null
}

sigstore_sign() {
    local payload="$1" bundle="$2"
    cosign sign-blob \
        --yes \
        --key "$SIGSTORE_PRIVATE_KEY" \
        --bundle "$bundle" \
        "$payload" >/dev/null
}

sigstore_verify() {
    local payload="$1" bundle="$2" public_key="$3"
    cosign verify-blob \
        --key "$public_key" \
        --bundle "$bundle" \
        "$payload" >/dev/null
}

sign_and_verify() {
    local payload="$1" public_ml_dsa="$2" public_sigstore="$3"
    local ml_dsa_signature="${payload}.mldsa87.sig"
    local sigstore_bundle="${payload}.sigstore.json"

    ml_dsa_sign "$payload" "$ml_dsa_signature"
    ml_dsa_verify "$payload" "$ml_dsa_signature" "$public_ml_dsa"
    sigstore_sign "$payload" "$sigstore_bundle"
    sigstore_verify "$payload" "$sigstore_bundle" "$public_sigstore"
}

verify_archive_paths() {
    local archive="$1"
    if tar -tzf "$archive" | awk '
        /^\// { bad = 1 }
        /(^|\/)\.\.($|\/)/ { bad = 1 }
        END { exit bad }
    '; then
        return 0
    fi
    die "archive contains an unsafe path: $(basename -- "$archive")"
}

build_release() {
    local version="$1" tag="$2" commit="$3" epoch="$4"
    local output_parent target_dir stage_parent source_parent verify_parent output_stage
    output_parent="$(dirname -- "$OUTPUT_DIR")"
    mkdir -p -- "$output_parent"
    WORK_DIR="$(mktemp -d "$REPO_ROOT/.cofre-release-work.XXXXXXXX")"
    target_dir="$WORK_DIR/target"
    stage_parent="$WORK_DIR/bundle"
    source_parent="$WORK_DIR/source"
    verify_parent="$WORK_DIR/verify"
    output_stage="$WORK_DIR/output"
    install -d -m 0755 "$stage_parent" "$source_parent" "$verify_parent" "$output_stage"

    local package_name bundle_root source_name source_root
    local binary_archive source_archive sbom manifest
    package_name="cofre-soberano-pq-v${version}-${RELEASE_TARGET}"
    bundle_root="$stage_parent/$package_name"
    source_name="cofre-soberano-pq-v${version}-source"
    source_root="$source_parent/$source_name"
    binary_archive="$output_stage/${package_name}.tar.gz"
    source_archive="$output_stage/${source_name}.tar.gz"
    sbom="$output_stage/cofre-soberano-pq-v${version}.cdx.json"
    manifest="$output_stage/release-manifest.json"

    copy_release_files "$bundle_root"

    note "building the standard workspace"
    SOURCE_DATE_EPOCH="$epoch" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_dir" \
    RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=." \
        cargo build --release --locked --workspace --target "$RELEASE_TARGET"

    local built_dir="$target_dir/$RELEASE_TARGET/release"
    install -m 0755 \
        "$built_dir/qaudit" \
        "$built_dir/qaudit-portal" \
        "$built_dir/qgateway" \
        "$bundle_root/bin/"
    check_binary_version "$bundle_root/bin/qaudit" "$version"
    check_binary_version "$bundle_root/bin/qaudit-portal" "$version"
    check_binary_version "$bundle_root/bin/qgateway" "$version"

    note "building the PKCS#11 qgateway variant"
    SOURCE_DATE_EPOCH="$epoch" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$target_dir" \
    RUSTFLAGS="--remap-path-prefix=$REPO_ROOT=." \
        cargo build --release --locked -p qgateway --features pkcs11 --target "$RELEASE_TARGET"
    install -m 0755 "$built_dir/qgateway" "$bundle_root/bin/qgateway-pkcs11"
    check_binary_version "$bundle_root/bin/qgateway-pkcs11" "$version"

    stage_source "$source_parent" "$source_name" "$commit"
    [[ -f "$source_root/Cargo.lock" ]] || die "source archive staging omitted Cargo.lock"
    scan_for_private_material "$source_root"
    scan_for_private_material "$bundle_root"

    make_archive "$stage_parent" "$package_name" "$binary_archive" "$epoch"
    make_archive "$source_parent" "$source_name" "$source_archive" "$epoch"
    gzip -t "$binary_archive"
    gzip -t "$source_archive"
    verify_archive_paths "$binary_archive"
    verify_archive_paths "$source_archive"

    note "generating the CycloneDX SBOM"
    (
        cd -- "$source_root"
        SOURCE_DATE_EPOCH="$epoch" \
        CARGO_BUILD_TARGET="$RELEASE_TARGET" \
            cargo cyclonedx \
            --format json \
            --spec-version 1.5 \
            --target "$RELEASE_TARGET" \
            --all-features \
            --all \
            --override-filename .cofre-component.cdx \
            --quiet
    )
    cmp -s "$REPO_ROOT/Cargo.lock" "$source_root/Cargo.lock" ||
        die "cargo-cyclonedx changed Cargo.lock"
    merge_component_sboms "$source_root" "$sbom" "$version"

    write_manifest \
        "$manifest" "$version" "$tag" "$commit" "$epoch" \
        "$binary_archive" "$source_archive" "$sbom" "$SOURCE_DIRTY"

    local public_ml_dsa="" public_sigstore="" payload
    if [[ "$MODE" == "release" ]]; then
        check_release_unchanged "$tag" "$commit"
        public_ml_dsa="$output_stage/release-mldsa87-public.pem"
        public_sigstore="$output_stage/release-sigstore-public.pem"
        openssl pkey -pubin -in "$ML_DSA_PUBLIC_KEY" -out "$public_ml_dsa" >/dev/null
        install -m 0644 "$SIGSTORE_PUBLIC_KEY" "$public_sigstore"
        for payload in "$binary_archive" "$source_archive" "$sbom" "$manifest"; do
            note "signing $(basename -- "$payload")"
            sign_and_verify "$payload" "$public_ml_dsa" "$public_sigstore"
        done
    fi

    local checksums="$output_stage/SHA256SUMS"
    (
        cd -- "$output_stage"
        find . -maxdepth 1 -type f \
            ! -name 'SHA256SUMS' \
            ! -name 'SHA256SUMS.*' \
            -printf '%f\0' | sort -z | xargs -0 sha256sum
    ) >"$checksums"
    if [[ "$MODE" == "release" ]]; then
        sign_and_verify "$checksums" "$public_ml_dsa" "$public_sigstore"
    fi

    (
        cd -- "$output_stage"
        sha256sum --check --strict SHA256SUMS
    )

    note "verifying the extracted binary bundle"
    tar -xzf "$binary_archive" -C "$verify_parent"
    local extracted="$verify_parent/$package_name"
    check_binary_version "$extracted/bin/qaudit" "$version"
    check_binary_version "$extracted/bin/qaudit-portal" "$version"
    check_binary_version "$extracted/bin/qgateway" "$version"
    check_binary_version "$extracted/bin/qgateway-pkcs11" "$version"
    [[ "$(stat -c '%a' "$extracted/systemd/qgateway.service")" == "644" ]] ||
        die "qgateway.service has the wrong mode in the binary bundle"
    cmp -s "$REPO_ROOT/Cargo.lock" "$source_root/Cargo.lock" ||
        die "source archive Cargo.lock differs from the release commit"

    check_release_unchanged "$tag" "$commit"
    [[ ! -e "$OUTPUT_DIR" ]] || die "output directory appeared during build"
    mv -T -- "$output_stage" "$OUTPUT_DIR"
    note "verified $MODE artifacts are in $OUTPUT_DIR"
}

main() {
    parse_args "$@"
    cd -- "$REPO_ROOT"
    check_prerequisites

    local version tag commit epoch
    version="$(workspace_version)"
    tag=""
    commit="$(git rev-parse HEAD)"
    epoch="$(git show -s --format=%ct "$commit")"
    [[ -z "$(git status --porcelain=v1 --untracked-files=normal)" ]] || SOURCE_DIRTY="true"
    if [[ "$MODE" == "release" ]]; then
        tag="v$version"
    fi
    check_build_state "$version" "$tag" "$commit"
    if [[ "$MODE" == "release" ]]; then
        check_signing_prerequisites
    fi
    build_release "$version" "$tag" "$commit" "$epoch"
}

main "$@"
