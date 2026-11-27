# Устой threat model

**Status:** implementation-stage model, not an independent security assessment.
The project has not received an independent cryptographic or application audit.

## Assets and trust boundaries

Assets include message plaintext, ratchet and handshake secrets, profile keys,
queue capabilities, contact labels, local encrypted state, and the decoy profile.
The relevant boundaries are:

1. The user's device and browser/Wasm runtime.
2. The network path between each client and its configured relay.
3. The relay process and its volatile queue state.
4. The human SAS/QR comparison channel.
5. Local IndexedDB, browser profile backups, exported `.ustoy` files, and OS-level
   storage.

The relay is not trusted with message contents or a user/contact graph. It is
trusted to provide best-effort queue storage, enforce configured limits, and
return the packet bytes it accepted. The browser and its operating system remain
trusted to execute the client honestly.

## Adversaries and protected scenarios

The intended adversary may passively record network traffic, operate or observe a
relay, retain ciphertext for later analysis, inspect media files before sending,
or gain brief physical access to a locked device. The implementation is intended
to reduce:

| Scenario | Relevant control | Residual risk |
|---|---|---|
| Passive network interception | Hybrid X25519 + ML-KEM-768 handshake; ratcheted ChaCha20-Poly1305 messages | Endpoint compromise, cryptographic implementation flaws, and active interception are not solved by passive confidentiality |
| Harvest-now/decrypt-later | ML-KEM-768 shared secret is combined with the classical handshake | This is not a guarantee against future cryptanalysis, faulty implementation, downgrade, or non-quantum side channels; independent review is outstanding |
| Relay building a contact graph | Independent one-way queues and capabilities; no account, sender, or stable global identifier | Relay/network observers can see IP address, queue ID, timing, frequency, and size bucket. Traffic padding does not hide timing or queue relationships inferred externally |
| EXIF/location leakage from images | Only JPEG/PNG are accepted and re-encoded in Rust/Wasm before encryption | This does not clean unsupported files (they are rejected), protect the endpoint, or establish that every codec defect is absent |
| Brief access to an unlocked device followed by Duress PIN | Duress path zeroizes real-profile key material in memory and requires a read-back-confirmed IndexedDB key-wrap deletion before activating decoy | The attacker may already have copied data or keys; browser/OS artifacts and external backups are not erased |

The handshake remains `UNVERIFIED` until the user compares the complete 48-bit
SAS (or QR representation) with the peer over a trusted out-of-band channel and
confirms it. Before confirmation, an active man-in-the-middle can establish
separate sessions. SAS comparison is an explicit user responsibility, not an
automatic identity assertion.

## Explicit non-goals and limits

- **Compromised endpoint:** malicious OS/browser extensions, keyloggers,
  screen/memory capture, injected JavaScript, and a compromised build host can
  observe plaintext or keys.
- **Physical media sanitization:** deleting the real key wrap and zeroizing
  application-held RAM keys is crypto-shredding at the application layer. It
  does not prove overwriting of SSD wear-levelled cells, filesystem journals,
  browser snapshots, swap, crash dumps, or OS/cloud backups.
- **External copies:** exported `.ustoy` files contain encrypted profile state
  and PIN-protected key wraps. An optional backup password adds an Argon2id-
  wrapped encryption layer. Duress cannot locate or delete copies stored
  elsewhere; backup handling may weaken the practical effect of Duress.
- **Traffic analysis:** fixed-size buckets obscure exact plaintext lengths only
  within a bucket. Message timing, frequency, queue identifiers, source IP, and
  relay availability remain observable. The browser live client cannot directly
  route Fetch through SOCKS5; Tor requires a Tor-enabled browser or native
  transport.
- **Availability:** queues and deduplication entries live in relay memory.
  Relay restart, TTL expiry, quota exhaustion, or network failure can delay or
  lose delivery. The sender's encrypted local outbox retries while the client
  can run and reuses the same packet/idempotency token.
- **Recipient proof:** relay `202` means accepted by the relay, not read or
  decrypted by the peer. The protocol does not create a sender-visible receipt.
- **Device, supply chain, and coercion:** no protection is claimed against
  malware, coerced disclosure of PINs, malicious dependencies, compromised
  distribution, or a hostile device owner.

## Data handled by the relay

The relay stores a destination queue identifier, a queue-scoped write capability,
an opaque padded packet, a random read receipt, and short-lived queue-local
idempotency digests. It does not intentionally log client IP addresses,
User-Agent headers, request bodies, or queue links. Network infrastructure,
container runtime, firewall, hosting provider, and Tor service logs must be
reviewed separately. The HTTP `/health` endpoint returns only an empty success
status.

## Operational requirements before production use

1. Obtain independent protocol and cryptographic review, including the binding
   of queue-routing fields to the authenticated handshake transcript.
2. Review Rust/Wasm dependency provenance, unsafe-code policy, browser build
   supply chain, Caddy/Tor configuration, and deployment logs.
3. Test Duress, backups, outbox retry/idempotency, persistence failure, and
   power-loss cases on supported browsers and storage implementations.
4. Define release signing, key rotation, incident response, and an update
   process. Reproducible hashes alone do not authenticate a publisher.
5. Reassess this model whenever protocol, relay, storage, backup, or deployment
   behavior changes.
