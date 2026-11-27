FROM --platform=linux/amd64 rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build

ARG SOURCE_DATE_EPOCH=1700000000
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/src=."

WORKDIR /src
COPY rust-toolchain.toml /src/rust-toolchain.toml
COPY Cargo.toml Cargo.lock /src/
COPY crypto-core/Cargo.toml /src/crypto-core/Cargo.toml
COPY crypto-core/src/ /src/crypto-core/src/
COPY crypto-wasm/Cargo.toml /src/crypto-wasm/Cargo.toml
COPY crypto-wasm/src/ /src/crypto-wasm/src/
COPY relay-server/Cargo.toml /src/relay-server/Cargo.toml
COPY relay-server/src/ /src/relay-server/src/
COPY relay-server/tests/ /src/relay-server/tests/

RUN cargo test --workspace --locked \
    && cargo build --workspace --release --locked

FROM scratch
COPY --from=build /src/target/release/libveyl_crypto_core.rlib /veyl_crypto_core.rlib
COPY --from=build /src/target/release/veyl-relay-server /veyl-relay-server
