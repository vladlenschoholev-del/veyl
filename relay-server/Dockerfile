FROM --platform=linux/amd64 rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build

ARG SOURCE_DATE_EPOCH=1700000000
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/workspace=."

WORKDIR /workspace
COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
COPY crypto-core/Cargo.toml crypto-core/Cargo.toml
COPY crypto-core/src crypto-core/src
COPY crypto-wasm/Cargo.toml crypto-wasm/Cargo.toml
COPY crypto-wasm/src crypto-wasm/src
COPY relay-server/Cargo.toml relay-server/Cargo.toml
COPY relay-server/src relay-server/src
COPY relay-server/tests relay-server/tests

RUN cargo test --locked -p veyl-relay-server \
    && cargo build --release --locked -p veyl-relay-server

FROM --platform=linux/amd64 rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
COPY --from=build /workspace/target/release/veyl-relay-server /usr/local/bin/veyl-relay-server
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/veyl-relay-server"]
