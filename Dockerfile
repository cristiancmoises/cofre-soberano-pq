# syntax=docker/dockerfile:1.7
#
# Cofre Soberano PQ — qaudit CLI container.
#
# Two-stage build: a builder layer with the full Rust toolchain, and a
# minimal distroless runtime carrying only the static-ish musl binary.
#
# Build:    docker build -t securityops/qaudit:0.1.0 .
# Run:      docker run --rm -v "$PWD":/data securityops/qaudit:0.1.0 verify --log /data/audit.qa

FROM rust:1.95-slim-bookworm AS builder

WORKDIR /src

# Cache deps first.
COPY Cargo.toml Cargo.lock ./
COPY crates/qaudit-core/Cargo.toml crates/qaudit-core/Cargo.toml
COPY crates/qaudit/Cargo.toml      crates/qaudit/Cargo.toml
RUN mkdir -p crates/qaudit-core/src crates/qaudit/src \
    && echo 'fn main(){}'           > crates/qaudit/src/main.rs \
    && echo 'pub fn _stub(){}'      > crates/qaudit-core/src/lib.rs \
    && cargo build --release --locked -p qaudit \
    && rm -rf crates/qaudit-core/src crates/qaudit/src

# Real build.
COPY crates ./crates
RUN cargo build --release --locked -p qaudit \
    && strip target/release/qaudit

# Distroless: only glibc + the binary. No shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="qaudit"
LABEL org.opencontainers.image.description="Post-quantum signed audit log (Cofre Soberano PQ)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.source="https://git.securityops.co/cristiancmoises/cofre-soberano-pq"
LABEL org.opencontainers.image.vendor="Security Ops"

COPY --from=builder /src/target/release/qaudit /usr/local/bin/qaudit

USER nonroot
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/qaudit"]
CMD ["--help"]
