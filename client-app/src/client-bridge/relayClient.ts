const PROTOCOL_VERSION = 1;
const QUEUE_ID_SIZE = 32;
const CAPABILITY_SIZE = 32;
const QUEUE_CREDENTIALS_SIZE = 1 + QUEUE_ID_SIZE + 2 * CAPABILITY_SIZE;
const QUEUE_ACCESS_SIZE = QUEUE_ID_SIZE + CAPABILITY_SIZE;
const RATCHET_HEADER_SIZE = 40;
const AEAD_NONCE_SIZE = 12;
const AEAD_TAG_SIZE = 16;
const PADDING_BUCKETS = [1024, 4096, 16384] as const;
const RECEIPT_SIZE = 16;
const MAX_BATCH_RECORDS = 32;

export interface RelayQueue {
  id: Uint8Array;
  writeCapability: Uint8Array;
  readCapability: Uint8Array;
}

export interface RelayedMessage {
  receipt: Uint8Array;
  payload: Uint8Array;
}

export interface RelayHealth {
  ok: boolean;
}

function isSupportedPayloadSize(size: number): boolean {
  return PADDING_BUCKETS.some(
    (bucket) => size === RATCHET_HEADER_SIZE + AEAD_NONCE_SIZE + bucket + AEAD_TAG_SIZE,
  );
}

function validateRelayUrl(relayUrl: string): URL {
  const url = new URL(relayUrl);
  const localHost = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(localHost && url.protocol === "http:")) {
    throw new Error("Relay must use HTTPS except for a local development server.");
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("Relay URL must be an origin without credentials, paths, or fragments.");
  }
  return url;
}

export class RelayClient {
  private readonly origin: string;

  constructor(relayUrl: string, private readonly fetcher: typeof fetch = fetch) {
    this.origin = validateRelayUrl(relayUrl).origin;
  }

  async createQueue(): Promise<RelayQueue> {
    const body = await this.request("/v1/queues", new Uint8Array());
    if (body.length !== QUEUE_CREDENTIALS_SIZE || body[0] !== PROTOCOL_VERSION) {
      throw new Error("Relay returned malformed queue credentials.");
    }
    return {
      id: body.slice(1, 33),
      writeCapability: body.slice(33, 65),
      readCapability: body.slice(65, 97),
    };
  }

  async send(
    queue: Pick<RelayQueue, "id" | "writeCapability">,
    encryptedPayload: Uint8Array,
    idempotencyKey = randomIdempotencyKey(),
  ): Promise<void> {
    if (!isSupportedPayloadSize(encryptedPayload.length)) {
      throw new Error("Encrypted packet does not match a supported fixed padding block.");
    }
    const packet = new Uint8Array(1 + QUEUE_ID_SIZE + CAPABILITY_SIZE + encryptedPayload.length);
    packet[0] = PROTOCOL_VERSION;
    packet.set(queue.id, 1);
    packet.set(queue.writeCapability, 1 + QUEUE_ID_SIZE);
    packet.set(encryptedPayload, 1 + QUEUE_ID_SIZE + CAPABILITY_SIZE);
    if (!/^[0-9a-f]{32}$/i.test(idempotencyKey)) {
      throw new Error("Relay idempotency key must be 128-bit hexadecimal.");
    }
    await this.request("/v1/queues/messages", packet, [202], {
      "idempotency-key": idempotencyKey.toLowerCase(),
    });
  }

  async health(): Promise<RelayHealth> {
    const response = await this.fetcher(`${this.origin}/health`, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (response.status !== 204 && response.status !== 200) {
      throw new Error(`Relay health check failed with HTTP ${response.status}.`);
    }
    return { ok: true };
  }

  async read(queue: RelayQueue): Promise<RelayedMessage[]> {
    const request = new Uint8Array(1 + QUEUE_ACCESS_SIZE);
    request[0] = PROTOCOL_VERSION;
    request.set(queue.id, 1);
    request.set(queue.readCapability, 1 + QUEUE_ID_SIZE);
    const body = await this.request("/v1/queues/read", request);
    if (body.length < 3 || body[0] !== PROTOCOL_VERSION) {
      throw new Error("Relay returned a malformed message batch.");
    }

    const count = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint16(1);
    if (count > MAX_BATCH_RECORDS) throw new Error("Relay batch exceeds the protocol limit.");
    const messages: RelayedMessage[] = [];
    let offset = 3;
    for (let index = 0; index < count; index += 1) {
      if (body.length - offset < RECEIPT_SIZE + 4) {
        throw new Error("Relay returned a truncated message record.");
      }
      const receipt = body.slice(offset, offset + RECEIPT_SIZE);
      offset += RECEIPT_SIZE;
      const length = new DataView(body.buffer, body.byteOffset + offset, 4).getUint32(0);
      offset += 4;
      if (!isSupportedPayloadSize(length) || body.length - offset < length) {
        throw new Error("Relay returned an invalid encrypted packet length.");
      }
      messages.push({ receipt, payload: body.slice(offset, offset + length) });
      offset += length;
    }
    if (offset !== body.length) throw new Error("Relay batch contains trailing bytes.");
    return messages;
  }

  async acknowledge(queue: RelayQueue, receipts: Uint8Array[]): Promise<void> {
    if (receipts.length > MAX_BATCH_RECORDS || receipts.some((receipt) => receipt.length !== RECEIPT_SIZE)) {
      throw new Error("Invalid relay acknowledgement batch.");
    }
    const request = new Uint8Array(1 + QUEUE_ACCESS_SIZE + 2 + receipts.length * RECEIPT_SIZE);
    request[0] = PROTOCOL_VERSION;
    request.set(queue.id, 1);
    request.set(queue.readCapability, 1 + QUEUE_ID_SIZE);
    const countOffset = 1 + QUEUE_ACCESS_SIZE;
    new DataView(request.buffer).setUint16(countOffset, receipts.length);
    let offset = countOffset + 2;
    for (const receipt of receipts) {
      request.set(receipt, offset);
      offset += RECEIPT_SIZE;
    }
    await this.request("/v1/queues/ack", request, [204]);
  }

  private async request(
    path: string,
    body: Uint8Array,
    successCodes = [200, 201],
    extraHeaders: Record<string, string> = {},
  ): Promise<Uint8Array> {
    const response = await this.fetcher(`${this.origin}${path}`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream", ...extraHeaders },
      body: body as BodyInit,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
    if (!successCodes.includes(response.status)) {
      throw new Error(`Relay request failed with HTTP ${response.status}.`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }
}

function randomIdempotencyKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function encodeQueueAccess(queue: RelayQueue, capability: "read" | "write"): Uint8Array {
  const token = capability === "read" ? queue.readCapability : queue.writeCapability;
  if (queue.id.length !== QUEUE_ID_SIZE || token.length !== CAPABILITY_SIZE) {
    throw new Error("Malformed relay queue credentials.");
  }
  return new Uint8Array([...queue.id, ...token]);
}
