# Stateless relay

The relay is an in-memory, store-and-forward service. It has no account,
sender, contact-graph, or cross-queue fields and does not install request
logging middleware. It does not persist messages to disk. A process restart
discards all queues and queued records.

## Binary API

All endpoints use `application/octet-stream`; protocol integers are big-endian.
See [`../docs/protocol-v1.md`](../docs/protocol-v1.md) for the packet envelope
and complete framing.

- `POST /v1/queues` returns the protocol version, random 32-byte queue ID,
  independent 32-byte write capability, and independent 32-byte read
  capability. Pass the write capability to the sender; retain the read
  capability at the recipient.
- `POST /v1/queues/messages` accepts one versioned relay packet. Only the
  capability and fixed payload size are checked; encrypted contents are opaque.
- `POST /v1/queues/read` accepts the queue ID and read capability and returns up
  to 32 records with random receipt IDs. Reads are repeatable until acked.
- `POST /v1/queues/ack` removes receipt IDs after the recipient has processed
  them. Acknowledgements are idempotent.

Messages expire after 24 hours; queues expire 30 days after creation.
The server prunes expired data on every request and once per second in the
background. Limits are 4,096 queues, 128 pending records per queue, 64 MiB
total queued payload, 60 writes/minute, and 120 reads or acknowledgements per
minute per queue. No IP or User-Agent rate-limit key is used.

## Local run and Tor

Run the local relay with `docker compose up --build`; by default it is bound
only to `127.0.0.1:8080`. `USTOY_RELAY_BIND` can select another host interface.
Start the optional Tor SOCKS5 sidecar with `docker compose --profile tor up
--build`; it binds to `127.0.0.1:9050`. Configure the client to use
`socks5h://127.0.0.1:9050`. The relay itself makes no outbound connections.

For an optional Tor hidden service, run a separately maintained Tor daemon on
the host and point its `HiddenServicePort` at `127.0.0.1:8080`, for example:

```text
HiddenServiceDir /var/lib/tor/ustoy-relay/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080
```

The Compose sidecar is a SOCKS proxy only; it does not create a persistent
onion address.
