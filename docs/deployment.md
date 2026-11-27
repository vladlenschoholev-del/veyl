# Self-hosted deployment

This guide covers Ubuntu/Debian, Docker Compose, a local development setup, and
direct relay binaries. Review [`threat-model.md`](threat-model.md) before
handling sensitive traffic. The implementation has not received an independent
security audit.

## Requirements

- Linux x86-64 host for the supplied production images.
- Rust toolchain pinned in `rust-toolchain.toml`, `cc`/build-essential, and
  `wasm-pack` 0.13.1 for source builds.
- Node.js 22.16.0 and npm for the UI.
- Docker Engine with the Compose plugin for the one-command deployment.
- A DNS name and inbound TCP 80/443 for public HTTPS. The default binding is
  loopback-only.

Install the system prerequisites on Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install --yes build-essential pkg-config libssl-dev git make
```

Install the pinned Rust toolchain by installing rustup, then run `rustup show
active-toolchain` in the repository. Install the matching `wasm-pack` with
`cargo install wasm-pack --version 0.13.1 --locked`. Install Node.js 22.16.0
from an approved, checksum-verified distribution.

## One-command Docker deployment

```sh
cp .env.example .env
# Edit .env: set USTOY_HOSTNAME and, for public service, USTOY_BIND=0.0.0.0
make run
```

`make run` builds the Rust/Wasm package, copies it only to
`client-app/public/crypto-wasm`, installs the locked npm dependencies, builds
the static UI, then starts the relay and Caddy reverse proxy. The relay is
reachable only on the private Compose network. Caddy serves the static client,
proxies `/v1/*` and `/health`, and discards access logs. For a public hostname,
Caddy provisions HTTPS automatically; DNS and ports 80/443 must already work.
Leave `ALLOWED_ORIGINS` empty for the same-origin reverse-proxy setup. If a
separate browser origin is required, set `ALLOWED_ORIGINS` to a comma-separated
list of exact `http(s)://host[:port]` origins; wildcard, path, and credential
entries are rejected.

Stop services with:

```sh
docker compose -f docker-compose.prod.yml down
```

The relay has volatile queue state. A container restart does not preserve
pending messages; the sender's encrypted local outbox can retry while its
profile remains available.

## Optional Tor service

```sh
USTOY_TOR=1 make run
docker compose -f docker-compose.prod.yml --profile tor exec tor \
  cat /var/lib/tor/ustoy-hidden/hostname
```

The optional Tor container publishes a v3 onion service to the Caddy frontend
and binds SOCKS5 to loopback port 9050. Keep the `tor_state` volume private:
it contains the hidden-service private key, and losing it changes the onion
address. The onion address file is public; do not export the hidden-service
private key. The browser Fetch transport does not use SOCKS5 directly. Use a
Tor-enabled browser for the onion URL or a separately configured native client.
The client can report that an onion endpoint was selected, but cannot prove that
the browser's Tor route is active.

## Development mode

```sh
make build-wasm
docker compose up --build relay
cd client-app
npm ci
npm run dev
```

Vite proxies `/v1` and `/health` to `127.0.0.1:8080`. The demo UI is not a
cryptographic client; select the Rust/Wasm live client and compare SAS before
sending.

## Direct relay binary

Build and run:

```sh
cargo build --release --locked -p veyl-relay-server
ALLOWED_ORIGINS=https://chat.example.org ./target/release/veyl-relay-server
```

The process listens on `0.0.0.0:8080`; put a TLS reverse proxy in front of it.
Do not enable request/access logs in that proxy, and remove forwarding headers
that expose client IPs to the relay. Without `ALLOWED_ORIGINS`, cross-origin
browser requests are disabled. `/health` returns `204 No Content` only.

## Reproducible build check

Run:

```sh
make verify
```

The script reports each check, builds release artifacts twice into separate
target directories, prints SHA-256 values for the `crypto-core` rlib and relay
binary, and fails if the hashes differ. It also runs formatting, strict Clippy,
Rust tests, Wasm build, `npm ci`, UI tests, and UI production build. A local
failure caused by a missing compiler/runtime is reported as a failure, not
silently treated as a pass.

For comparison, use the same source revision, pinned Rust toolchain, target,
environment (`SOURCE_DATE_EPOCH`, `CARGO_INCREMENTAL=0`, path remapping), and
OS/container image. The hash comparison checks deterministic output under those
conditions; it does not prove source safety, publisher identity, dependency
integrity, or that a deployed binary came from the reviewed source. Preserve
the complete verification output with the source revision when handing the
product to another operator.
