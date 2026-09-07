# syntax=docker/dockerfile:1.7
#
# Cofre Soberano PQ — qaudit CLI container.
#
# The complete workspace is copied because Cargo must resolve every workspace
# member even when only qaudit is selected. The runtime is a minimal Debian 12
# distroless image carrying the dynamically linked glibc binary.
#
# Build:    docker build -t cofre-soberano-pq/qaudit:local .
# Run:      docker run --rm -v "$PWD":/data cofre-soberano-pq/qaudit:local verify --log /data/audit.qa

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /src

# Cargo resolves the full workspace before selecting -p qaudit, so retain every
# member manifest and source tree. BuildKit cache mounts keep repeat builds fast
# without maintaining fragile placeholder crates.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p qaudit \
    && install -m 0755 target/release/qaudit /usr/local/bin/qaudit

# Distroless contains glibc and the runtime libraries required by the builder's
# Debian target. It has no shell or package manager.
FROM gcr.io/distroless/cc-debian12:nonroot

ARG VERSION
ARG VCS_REF
ARG CREATED

LABEL org.opencontainers.image.title="qaudit"
LABEL org.opencontainers.image.description="Post-quantum signed audit log (Cofre Soberano PQ)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later OR LicenseRef-Cofre-Soberano-PQ-Commercial"
LABEL org.opencontainers.image.source="https://git.securityops.co/cristiancmoises/cofre-soberano-pq"
LABEL org.opencontainers.image.vendor="Security Ops"
LABEL org.opencontainers.image.version="$VERSION"
LABEL org.opencontainers.image.revision="$VCS_REF"
LABEL org.opencontainers.image.created="$CREATED"

COPY --from=builder --chmod=0755 /usr/local/bin/qaudit /usr/local/bin/qaudit
COPY --chmod=0644 LICENSE-AGPL LICENSE-COMMERCIAL NOTICE /usr/share/licenses/qaudit/

USER nonroot
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/qaudit"]
CMD ["--help"]
