#!/usr/bin/env python3
"""Generate distribution candidates from a completed, checksummed source release.

This command does not publish packages or submit contributions.  Build and lint
each candidate in its target distribution before sending it for review.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tomllib
from urllib.parse import urlsplit
from urllib.request import urlopen


DESCRIPTION = "Post-quantum signed audit logs and TCP gateway"
HOMEPAGE = "https://git.securityops.co/cristiancmoises/cofre-soberano-pq"
MAINTAINER = "Cristian Cezar Moisés <sac@securityops.co>"


NIX = '''{ lib, rustPlatform, fetchurl }:

rustPlatform.buildRustPackage {
  pname = "cofre-soberano-pq";
  version = "@VERSION@";
  src = fetchurl {
    url = "@URL@";
    hash = "@SRI@";
  };
  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [ "--workspace" ];
  cargoTestFlags = [ "--workspace" ];
  buildFeatures = [ "qgateway/pkcs11" ];
  postInstall = ''
    install -Dm644 LICENSE-AGPL "$out/share/licenses/cofre-soberano-pq/LICENSE-AGPL"
    install -Dm644 NOTICE "$out/share/doc/cofre-soberano-pq/NOTICE"
    install -m644 README.md README.pt-BR.md "$out/share/doc/cofre-soberano-pq/"
    cp -r docs "$out/share/doc/cofre-soberano-pq/"
    cp -r screenshots "$out/share/doc/cofre-soberano-pq/"
  '';
  meta = {
    description = "@DESCRIPTION@";
    homepage = "@HOMEPAGE@";
    license = lib.licenses.agpl3Plus;
    mainProgram = "qaudit";
    platforms = lib.platforms.linux;
  };
}
'''

ARCH = '''# Maintainer: @MAINTAINER@
pkgname=cofre-soberano-pq
pkgver=@VERSION@
pkgrel=1
pkgdesc='@DESCRIPTION@'
arch=('x86_64' 'aarch64')
url='@HOMEPAGE@'
license=('AGPL-3.0-or-later')
depends=('gcc-libs' 'glibc')
makedepends=('cargo')
source=('@URL@')
sha256sums=('@SHA256@')

prepare() {
    cd "$srcdir/@ROOT@" || return
    cargo fetch --locked
}

build() {
    cd "$srcdir/@ROOT@" || return
    cargo build --release --frozen --workspace --features qgateway/pkcs11
}

check() {
    cd "$srcdir/@ROOT@" || return
    cargo test --frozen --workspace --features qgateway/pkcs11
}

package() {
    cd "$srcdir/@ROOT@" || return
    install -Dm755 target/release/{qaudit,qaudit-portal,qgateway} -t "$pkgdir/usr/bin/"
    install -Dm644 LICENSE-AGPL -t "$pkgdir/usr/share/licenses/$pkgname/"
    install -Dm644 README.md README.pt-BR.md NOTICE -t "$pkgdir/usr/share/doc/$pkgname/"
    cp -r docs "$pkgdir/usr/share/doc/$pkgname/"
    cp -r screenshots "$pkgdir/usr/share/doc/$pkgname/"
}
'''

ALPINE = '''# Contributor: @MAINTAINER@
# Maintainer: @MAINTAINER@
pkgname=cofre-soberano-pq
pkgver=@VERSION@
pkgrel=0
pkgdesc="@DESCRIPTION@"
url="@HOMEPAGE@"
arch="x86_64 aarch64"
license="AGPL-3.0-or-later"
makedepends="cargo cargo-auditable"
subpackages="$pkgname-doc"
options="net"
source="@URL@"
builddir="$srcdir/@ROOT@"

prepare() {
    default_prepare
    cargo fetch --target="$CTARGET" --locked
}

build() {
    cargo auditable build --release --frozen --workspace --features qgateway/pkcs11
}

check() {
    cargo test --frozen --workspace --features qgateway/pkcs11
}

package() {
    for binary in qaudit qaudit-portal qgateway; do
        install -Dm755 "target/release/$binary" "$pkgdir/usr/bin/$binary"
    done
    install -Dm644 LICENSE-AGPL "$pkgdir/usr/share/licenses/$pkgname/LICENSE-AGPL"
    install -Dm644 README.md README.pt-BR.md NOTICE -t "$pkgdir/usr/share/doc/$pkgname/"
    cp -r docs "$pkgdir/usr/share/doc/$pkgname/"
    cp -r screenshots "$pkgdir/usr/share/doc/$pkgname/"
}

sha512sums="
@SHA512@  @ARCHIVE@
"
'''

FREEBSD = '''PORTNAME=\tcofre-soberano-pq
DISTVERSION=\t@VERSION@
CATEGORIES=\tsecurity
MASTER_SITES=\t@BASEURL@
DISTNAME=\t@ROOT@

MAINTAINER=\tsac@securityops.co
COMMENT=\t@DESCRIPTION@
WWW=\t\t@HOMEPAGE@

LICENSE=\tAGPLv3+
LICENSE_FILE=\t${WRKSRC}/LICENSE-AGPL

USES=\t\tcargo
CARGO_BUILD_ARGS=\t--workspace
CARGO_TEST_ARGS=\t--workspace
CARGO_FEATURES=\tqgateway/pkcs11
CARGO_INSTALL=\tno

PLIST_FILES=\tbin/qaudit bin/qaudit-portal bin/qgateway
PORTDOCS=\tREADME.md README.pt-BR.md NOTICE docs screenshots
OPTIONS_DEFINE=\tDOCS

do-install:
.for binary in qaudit qaudit-portal qgateway
\t${INSTALL_PROGRAM} ${CARGO_TARGET_DIR}/release/${binary} ${STAGEDIR}${PREFIX}/bin/
.endfor

do-install-DOCS-on:
\t@${MKDIR} ${STAGEDIR}${DOCSDIR}
\t${INSTALL_DATA} ${WRKSRC}/README.md ${WRKSRC}/README.pt-BR.md ${WRKSRC}/NOTICE ${STAGEDIR}${DOCSDIR}/
\tcd ${WRKSRC} && ${COPYTREE_SHARE} docs ${STAGEDIR}${DOCSDIR}
\tcd ${WRKSRC} && ${COPYTREE_SHARE} screenshots ${STAGEDIR}${DOCSDIR}

.include <bsd.port.mk>
'''


def render(template, values):
    for key, value in values.items():
        template = template.replace(f"@{key}@", value)
    return template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--crate-cache", type=Path,
                        default=Path.home() / ".cache/cofre-packaging/crates")
    args = parser.parse_args()
    parsed = urlsplit(args.source_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.query
            or parsed.fragment or parsed.username or parsed.password
            or not re.fullmatch(r"[A-Za-z0-9:/._+~%-]+", args.source_url)):
        parser.error("source URL must be a plain HTTPS release URL")
    filename = args.source_archive.name
    match = re.fullmatch(r"cofre-soberano-pq-v(\d+\.\d+\.\d+)-source\.tar\.gz", filename)
    if not match or parsed.path.rsplit("/", 1)[-1] != filename:
        parser.error("archive name and source URL must name the same versioned source release")
    version = match.group(1)
    root = filename.removesuffix(".tar.gz")
    with tarfile.open(args.source_archive, "r:gz") as archive:
        def read_member(name):
            member = archive.getmember(f"{root}/{name}")
            if not member.isfile() or member.size > 5_000_000:
                parser.error(f"invalid source archive member: {name}")
            return archive.extractfile(member).read()
        manifest = tomllib.loads(read_member("Cargo.toml").decode())
        source_epoch = int(archive.getmember(f"{root}/Cargo.toml").mtime)
        lock_bytes = read_member("Cargo.lock")
    if manifest["workspace"]["package"]["version"] != version:
        parser.error("archive version disagrees with Cargo.toml")
    packages = tomllib.loads(lock_bytes.decode())["package"]
    for package in packages:
        source = package.get("source")
        if source and source != "registry+https://github.com/rust-lang/crates.io-index":
            parser.error(f"unsupported dependency source: {source}")
    if args.output.exists():
        parser.error("output directory already exists; use a fresh directory")
    digest = hashlib.file_digest(args.source_archive.open("rb"), "sha256")
    values = {
        "VERSION": version, "ROOT": root, "ARCHIVE": filename,
        "URL": args.source_url, "BASEURL": args.source_url.rsplit("/", 1)[0] + "/",
        "SHA256": digest.hexdigest(),
        "SHA512": hashlib.file_digest(args.source_archive.open("rb"), "sha512").hexdigest(),
        "SRI": "sha256-" + base64.b64encode(digest.digest()).decode(),
        "DESCRIPTION": DESCRIPTION, "HOMEPAGE": HOMEPAGE, "MAINTAINER": MAINTAINER,
    }
    registry = [package for package in packages if package.get("source")]
    args.crate_cache.mkdir(parents=True, exist_ok=True)

    def fetch_crate(package):
        name = f"{package['name']}-{package['version']}"
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ValueError(f"invalid crate name: {name}")
        path = args.crate_cache / f"{name}.crate"
        if not path.exists():
            url = f"https://static.crates.io/crates/{package['name']}/{name}.crate"
            with urlopen(url, timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != package["checksum"]:
                raise ValueError(f"crate checksum mismatch: {name}")
            temporary = path.with_suffix(".part")
            temporary.write_bytes(data)
            temporary.replace(path)
        with path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        if checksum != package["checksum"]:
            raise ValueError(f"cached crate checksum mismatch: {name}")
        return name, checksum, path.stat().st_size

    with ThreadPoolExecutor(max_workers=4) as executor:
        crates = sorted(executor.map(fetch_crate, registry))
    args.output.mkdir(parents=True)
    for relative, template in {
        "nixpkgs/package.nix": NIX, "arch/PKGBUILD": ARCH,
        "alpine/APKBUILD": ALPINE, "freebsd/Makefile": FREEBSD,
    }.items():
        path = args.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(template, values))
    (args.output / "nixpkgs/Cargo.lock").write_bytes(lock_bytes)
    (args.output / "freebsd/pkg-descr").write_text(
        "Cofre Soberano PQ provides qaudit for signing and verifying audit logs,\n"
        "qaudit-portal for viewing them, and qgateway for forwarding TCP traffic\n"
        "over an experimental post-quantum transport. It supports ML-DSA\n"
        "signatures, BLAKE3 audit chains, and PKCS#11 signing backends.\n")
    continuation = " " + "\\" + "\n\t\t"
    (args.output / "freebsd/Makefile.crates").write_text(
        "CARGO_CRATES=\t" + continuation.join(name for name, _, _ in crates) + "\n")
    distinfo = [f"TIMESTAMP = {source_epoch}",
                f"SHA256 ({filename}) = {values['SHA256']}",
                f"SIZE ({filename}) = {args.source_archive.stat().st_size}"]
    for name, checksum, size in crates:
        distinfo.extend([f"SHA256 (rust/crates/{name}.crate) = {checksum}",
                         f"SIZE (rust/crates/{name}.crate) = {size}"])
    (args.output / "freebsd/distinfo").write_text("\n".join(distinfo) + "\n")
    (args.output / "source.json").write_text(json.dumps({
        "version": version, "source_url": args.source_url,
        "sha256": values["SHA256"], "locked_registry_crates": len(crates),
        "validation": "Generated candidates; target distribution builds and lint are still required.",
    }, indent=2) + "\n")
    print(f"Generated four distribution candidates in {args.output}")


if __name__ == "__main__":
    main()
