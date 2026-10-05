# syntax=docker/dockerfile:1
#
# The OpenLFCP reference server image (LFCP-055).
#
# Build context: the directory that holds the `server/` and `sdk-rs/`
# checkouts side by side, sdk-rs at the commit in server/sdk-rs.lock (the
# CI layout). deploy/check.sh verifies that before building; compose.yaml
# sets the context. Only the Rust sources enter the context
# (Dockerfile.dockerignore).

ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY sdk-rs/Cargo.toml sdk-rs/
COPY sdk-rs/crates sdk-rs/crates
COPY server/Cargo.toml server/Cargo.lock server/
COPY server/crates server/crates
WORKDIR /src/server
# --locked: exactly the dependency versions of server/Cargo.lock.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/server/target \
    cargo build --release --locked -p lfcp-server \
    && install -D -m 0755 target/release/lfcp-server /out/lfcp-server \
    && mkdir -p /out/state

# glibc and libgcc only, no shell or package manager; runs as uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/lfcp-server /usr/local/bin/lfcp-server
COPY server/deploy/server.toml /etc/lfcp/server.toml
# The state directory (server ID and SQLite database), owned by the
# runtime user so a new named volume inherits that ownership.
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/lfcp
VOLUME ["/var/lib/lfcp"]
USER nonroot:nonroot
EXPOSE 7820
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/lfcp-server", "--health-check", "--config", "/etc/lfcp/server.toml"]
ENTRYPOINT ["/usr/local/bin/lfcp-server"]
CMD ["--config", "/etc/lfcp/server.toml"]
