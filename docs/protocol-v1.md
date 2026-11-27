# Ustoy protocol proposal, version 1

This is the version-1 protocol proposal. It specifies the handshake, encrypted
snapshots, duress contract, and relay envelope; it is not a claim of
interoperability with SimpleX or Signal. The implementation still requires
independent protocol and security review before production use.

## Identity and queues

There is no account identifier or reusable public identity. For every contact,
each endpoint creates independent 256-bit random queue IDs and independent
256-bit write capabilities using the operating system CSPRNG. A queue ID and its
capability are disclosed only to the intended peer. The receiving endpoint gives
the peer a write capability; the sender learns no other queue belonging to that
endpoint. A relay stores each queue and its pending opaque records independently,
with no account or cross-queue relationship.

A one-time invite carries an ephemeral X25519 public key, an ML-KEM-768
encapsulation key, and the inviter's queue ID/write capability. Its version-1
binary form is `USTOYI1\0` + 64-byte queue access + encoded offer; the reply is
`USTOYR1\0` + inviter queue access + invitee queue access + encoded response.
Read capabilities are never included. The invite is transferred out of band as
a URL or QR code and must be treated as a bearer secret. The browser adapter
rejects reuse on that device; the relay does not enforce invite expiry or
single-use semantics.

The current 48-bit SAS authenticates the hybrid handshake keys, but does not
bind either queue-access field into its transcript. Queue-routing integrity
therefore depends on transferring the invite and reply through the intended
out-of-band channel. This limitation must be resolved by adding queue context to
the authenticated transcript before production use.

## Hybrid handshake

1. The inviter generates an ephemeral X25519 key pair and an ML-KEM-768 key
   pair. The invite publishes their public keys.
2. The invitee generates an ephemeral X25519 key pair, performs X25519 with the
   inviter's ephemeral public key, and encapsulates to the ML-KEM public key.
   The response carries the invitee's X25519 public key and the ML-KEM
   ciphertext.
3. Both endpoints compute the same 32-byte X25519 secret and ML-KEM secret.
   HKDF-SHA-256 derives the initial root secret from their concatenation, salted
   and domain-separated by a hash of the complete ordered handshake transcript.
   The inviter consumes its one-time ML-KEM decapsulation key.
4. Both endpoints display the same 48-bit authentication string derived from
   the complete transcript; users compare it out of band before trusting the
   exchange. The same ephemeral X25519 pair initializes the Double Ratchet. The
   inviter initializes a sending chain and the invitee the matching receiving
   chain. Every later DH ratchet step derives a new root key and chain key. Each
   message consumes one chain key and uses ChaCha20-Poly1305 with the ratchet
   header as associated data. Skipped message keys are bounded.
5. Without that check, an attacker who replaces the invite can perform an
   active man-in-the-middle attack. The protocol intentionally has no
   long-lived signing identity.

The symmetric message authentication and absence of persistent signatures
provide deniability properties, not proof that a message was authored by a
particular person. Deniability is not a substitute for authenticating the
initial QR/invite.

## Relay envelope and HTTP binary API

All integers are unsigned big-endian. The relay record is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Protocol version (`0x01`) |
| 1 | 32 | Random destination queue ID |
| 33 | 32 | Per-queue write capability |
| 65 | variable | Opaque encrypted payload |

There is no sender field. The capability is a write token for one destination
queue, not a user identifier. Queue creation returns three independent random
32-byte
values: queue ID, write capability, and independent read capability. Share only
the write capability with the sender and keep the read capability with the
recipient. Queue creation response is version byte `0x01` followed by those
values in that order (97 bytes total).

The HTTP API uses `application/octet-stream` and has no request logging. Relay
credentials are bearer capabilities; use TLS termination or a Tor hidden
service for non-local deployment (the server binary itself serves HTTP):

| Method and path | Request body | Response |
|---|---|---|
| `GET /health` | empty | `204`; empty response, no build/version metadata |
| `POST /v1/queues` | empty | `201`; version byte + queue ID + write token + read token |
| `POST /v1/queues/messages` | complete relay record above; optional `Idempotency-Key` HTTP header with a 128-bit hex token | `202` after enqueue or matching retry |
| `POST /v1/queues/read` | version byte + queue ID + read token (65 bytes) | version byte + `u16` record count + records |
| `POST /v1/queues/ack` | version byte + queue ID + read token + `u16` count + receipt IDs | `204` |

`Idempotency-Key` is generated randomly per encrypted outbox item and remains
stable across its retries. The relay scopes the token and ciphertext digest to
one queue for the message TTL; a matching retry returns `202` without adding a
second record, while reuse with different ciphertext returns `409`. The dedup
cache has a global bound; when full, new writes receive `503` until entries
expire. This queue-local transport token is not a user or sender identifier.

Each read record is a 16-byte random receipt ID, a 4-byte payload length, and
the opaque encrypted payload. A read does not delete records: the recipient
acknowledges receipt IDs after successful processing. Acknowledgements are
idempotent and only remove the recipient's queued copy; they do not produce a
sender-visible delivery receipt. A read returns at most 32 records; further
records remain available for subsequent reads. Unknown versions, malformed
lengths, invalid capabilities, and non-bucket payloads are rejected. The server
stores neither sender identifiers nor relationships between queues.

The encrypted payload begins with a ratchet header (32-byte DH public key,
4-byte previous sending-chain length, 4-byte message number), followed by a
12-byte AEAD nonce and ciphertext. The header is authenticated as associated
data. Before encryption, plaintext is encoded as a 4-byte length followed by
plaintext and CSPRNG padding, selecting the smallest fitting padded-plaintext
bucket: 1024, 4096, or 16384 bytes. Consequently, encrypted payload lengths are
1092, 4164, or 16452 bytes (40-byte header + 12-byte nonce + padded plaintext +
16-byte AEAD tag); total relay-record lengths are 1157, 4229, or 16517 bytes.
The relay validates only these lengths and must not parse payload contents.

## Local encrypted session snapshots

The local `StateStorage` adapter persists each `SessionState` as a binary
snapshot. The postcard-encoded plaintext is versioned and includes the
verification state, the Double Ratchet root and chain keys, local DH secret,
remote DH public key, counters, and skipped message keys. Skipped keys are
serialized in deterministic `(DH public key, message number)` order and restore
rejects duplicates or more than 2,000 keys. The plaintext is capped at 1 MB.

The snapshot envelope is the 8-byte magic `USTOYSS1`, a fresh 12-byte nonce,
then ChaCha20-Poly1305 ciphertext and its 16-byte tag. The magic is associated
data. The AEAD key is the unlocked random profile data key; that key is wrapped
locally by the Argon2id PIN vault. State encoding is deterministic, while the
encrypted envelope intentionally varies because of its random nonce. The
`local_session_key` used by the storage adapter is local-only and is never sent
to the relay.

## Metadata limits and relay behavior

The envelope hides sender identity from the relay but not the source IP, timing,
queue destination, queue activity, or selected size bucket. The optional
self-hosted Tor service provides an onion endpoint and SOCKS5 listener, but the
browser Fetch API cannot directly use SOCKS5. Batching, optional jitter, and
dummy traffic remain separate features to be designed and tested. Dummy traffic
must use indistinguishable queue records and must not create identifiable
server-side accounts or endpoints.

The implementation keeps queue data in volatile memory only, with bounded
queue count, per-queue depth, global stored bytes, rate limits per queue
capability, and a 24-hour message TTL. Queues expire 30 days after creation.
Expiration is checked on every request and by a one-second cleanup task;
successful acknowledgements remove delivered records immediately. A process
restart loses all queued packets. The relay does not log IP addresses,
User-Agent headers, queue activity, or request bodies. These controls must not
add stable client identifiers. Self-hosted relays and separate inbound and
outbound relay URLs are client configuration, not account state.

CORS is disabled unless `ALLOWED_ORIGINS` is configured with a comma-separated
list of exact origins; wildcard origins, credentials, and URL paths are rejected.
The production Caddy setup is same-origin by default and discards access logs.

## Device keys and duress

The local database should be encrypted with a random data-encryption key. A
PIN-derived Argon2id key wraps that key; the profile and wrapped key are stored
locally. The duress PIN opens a separately prepared decoy profile and instructs
the storage layer to remove the real wrapped key. The core can zeroize key
buffers it owns. It cannot guarantee physical erasure of database pages,
filesystem journals, SSD wear-levelled blocks, swap, crash dumps, or backups.
The client must avoid cloud backups, keep key material out of logs, minimize
copies, and test the storage/keychain deletion path on supported devices.
Argon2id raises the cost of offline guessing but cannot make a short numeric PIN
high-entropy. Production unlock must enforce device-level rate limits or use a
hardware-backed secret; a PIN alone is not adequate protection for a copied
vault.

`PinVault` is an in-memory key-wrapping primitive, not an encrypted database or
persistent secure-wipe implementation. `KeyWrapStorage` must durably mark
`DURESS_PENDING_CLEANUP`, delete the real-key wrapper, and only then return a
deletion receipt. The core zeroizes its owned runtime data key and ratchet
sessions before requesting persistent deletion. If deletion fails, the runtime
stays pending and no decoy key is released; startup retries deletion before
unlocking any profile. The adapter must implement pending/active state changes
durably and make deletion idempotent.

This is crypto-shredding plus deletion of the persistent key wrapper, not
physical erasure. It cannot guarantee overwriting SSD sectors, filesystem
journals, swap, crash dumps, or operating-system/cloud backups. The real profile
may remain recoverable after a crash before the pending marker is committed.

## Metadata stripping and supported inputs

Raster JPEG/PNG files are decoded and re-encoded before encryption; this
discards embedded metadata rather than attempting to patch selected tags.
Unsupported image formats, audio, and documents must be rejected until a
format-specific sanitizer is implemented and tested. Passing an unsupported
file through unchanged would be unsafe.

## Stage-2 acceptance boundary

Before any UI work, the handshake, ratchet, padding, PIN-vault, image sanitizer,
encrypted session snapshots, duress storage adapter, and relay service need
focused tests and independent protocol/security review. Relay record retrieval
uses explicit acknowledgements so a transport retry does not silently consume a
message. The client-side Tor transport, local P2P, offline bundle format, and
end-to-end application release builds remain later milestones.
