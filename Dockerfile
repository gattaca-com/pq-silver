# syntax=docker/dockerfile:1

# `blst`, `hashtree-rs` and `mimalloc` compile C (and hashtree, assembly), and
# both `build.rs` scripts shell out to `buf`.
FROM rust:1.99.1-bookworm AS builder

ARG BUF_VERSION=1.67.0
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL -o /usr/local/bin/buf \
      "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-$(uname -m)" && \
    chmod +x /usr/local/bin/buf

WORKDIR /silver
COPY . .

ARG SILVER_BUILD_COMMIT

# `--locked` inside: the committed Cargo.lock is under a publish-age cooldown
# (see the justfile), so resolution must not drift in the image. The script
# builds for any x86-64 CPU, with leanVM's prover tiers picked at run time.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/silver/target \
    scripts/build-prod.sh --features silver/metrics --bin silver --bin silver_surfer --bin silver-vc && \
    cp target/release-prod/silver target/release-prod/silver_surfer target/release-prod/silver-vc /usr/local/bin/

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.source="https://github.com/gattaca-com/silver" \
    org.opencontainers.image.licenses="MIT"

# Without this the tracing subscriber writes to rolling files under LOG_PATH,
# where `docker logs` never sees them.
ENV LOG_STDOUT=1

ENTRYPOINT ["/usr/local/bin/silver"]

# Release builds package the exact binaries attached to the GitHub release.
FROM runtime AS release
COPY --chmod=755 silver-linux-x86_64 /usr/local/bin/silver
COPY --chmod=755 silver_surfer-linux-x86_64 /usr/local/bin/silver_surfer
COPY --chmod=755 silver-vc-linux-x86_64 /usr/local/bin/silver-vc

FROM runtime AS silver
COPY --from=builder /usr/local/bin/silver /usr/local/bin/silver_surfer /usr/local/bin/silver-vc /usr/local/bin/
