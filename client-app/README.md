# Ustoy client

The existing chat/invitation/security screens remain an explicitly labeled UI
demo. A separate **Rust/Wasm live client** view uses `WasmClientBridge`, the
binary `RelayClient`, and `EncryptedIndexedDbStorage` for real local crypto and
relay exchange. The legacy demo screens are not a secure messenger.

The Wasm bridge calls the Rust X25519 + ML-KEM-768 handshake, SAS confirmation,
Double Ratchet, fixed-block padding, image re-encoding, encrypted session
snapshots, and Argon2id PIN key wraps. IndexedDB stores encrypted local records
and encrypted session snapshots; real-key wrapper deletion is gated by a
transaction/read-back receipt. This confirms application-level deletion only:
it cannot guarantee physical erasure from SSD sectors, filesystem journals,
swap, crash dumps, or operating-system backups.

If the relay is unavailable, the live client atomically stores the encrypted
packet, its stable idempotency token, and the advanced ratchet snapshot in the
profile-encrypted IndexedDB outbox. Retries reuse the exact ciphertext, on
network restoration and while the client is open; they never ratchet-encrypt
the plaintext again. Relay acknowledgements delete records from the recipient's
queue; they do not create a sender-visible delivery receipt.

The client probes `/health` and reports Wasm and relay availability. Browser
Fetch cannot itself route through SOCKS5; the diagnostic reports this limitation
or an onion endpoint selection without claiming to verify the browser's Tor
route. The `.ustoy` export contains encrypted local stores and Argon2id-protected
key wraps. An optional backup password adds a second Argon2id-wrapped
ChaCha20-Poly1305 layer. Backups are external copies and survive Duress cleanup.

## Run locally

Build Wasm and start the relay from the repository root:

```sh
make build-wasm
docker compose up --build relay
```

Start the UI from `client-app/`:

```sh
npm ci
npm run dev
```

Open the localhost URL printed by Vite. Verify with `npm test && npm run build`.
The full pinned Linux workflow is `.github/workflows/verify.yml`.
