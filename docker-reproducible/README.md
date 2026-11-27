# Reproducible workspace build

The Dockerfile builds and tests the complete Rust workspace with an immutable
Rust image digest, the root lockfile, disabled incremental compilation, and a
fixed `SOURCE_DATE_EPOCH`. The build targets `linux/amd64`; other architectures
require a separately pinned and compared build.

Build and extract both release artifacts:

```sh
docker build --platform linux/amd64 -f docker-reproducible/Dockerfile -t ustoy-build .
docker create --name ustoy-artifacts ustoy-build
docker cp ustoy-artifacts:/veyl_crypto_core.rlib ./veyl_crypto_core.rlib
docker cp ustoy-artifacts:/veyl-relay-server ./veyl-relay-server
docker rm ustoy-artifacts
sha256sum veyl_crypto_core.rlib veyl-relay-server
```

Rebuild from the same source revision, Docker/BuildKit version, platform, and
`SOURCE_DATE_EPOCH`, then compare both artifact hashes.
