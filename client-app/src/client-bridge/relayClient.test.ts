import { describe, expect, it, vi } from "vitest";
import { RelayClient, type RelayQueue } from "./relayClient";

const queue: RelayQueue = {
  id: new Uint8Array(32).fill(1),
  writeCapability: new Uint8Array(32).fill(2),
  readCapability: new Uint8Array(32).fill(3),
};

function response(status: number, body: Uint8Array = new Uint8Array()): Response {
  return new Response(status === 204 ? null : body, { status });
}

describe("RelayClient binary protocol", () => {
  it("creates queues from the fixed binary credential response", async () => {
    const credentials = new Uint8Array(97);
    credentials[0] = 1;
    credentials.set(queue.id, 1);
    credentials.set(queue.writeCapability, 33);
    credentials.set(queue.readCapability, 65);
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => response(201, credentials),
    );

    await expect(new RelayClient("https://relay.example", fetcher).createQueue()).resolves.toEqual(
      queue,
    );
    expect(fetcher).toHaveBeenCalledWith(
      "https://relay.example/v1/queues",
      expect.objectContaining({ credentials: "omit", redirect: "error" }),
    );
  });

  it("sends a fixed-size packet with queue write capability and rejects other sizes", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) => response(202),
    );
    const client = new RelayClient("http://127.0.0.1:8080", fetcher);
    const payload = new Uint8Array(40 + 12 + 1024 + 16).fill(9);

    await client.send(queue, payload);
    const packet = fetcher.mock.calls[0]?.[1]?.body as Uint8Array;
    expect(packet.length).toBe(65 + payload.length);
    expect(packet[0]).toBe(1);
    expect(packet.slice(1, 33)).toEqual(queue.id);
    expect(packet.slice(33, 65)).toEqual(queue.writeCapability);
    expect(packet.slice(65)).toEqual(payload);
    expect(fetcher.mock.calls[0]?.[1]?.headers).toHaveProperty("idempotency-key");
    await expect(client.send(queue, new Uint8Array(100))).rejects.toThrow(
      "fixed padding block",
    );
  });

  it("uses a stable caller-supplied idempotency key and checks the metadata-free health endpoint", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
      response(String(input).endsWith("/health") ? 204 : 202),
    );
    const client = new RelayClient("https://relay.example", fetcher);
    const key = "aabbccddeeff00112233445566778899";
    await client.send(queue, new Uint8Array(40 + 12 + 1024 + 16), key);
    expect(fetcher.mock.calls[0]?.[1]?.headers).toMatchObject({ "idempotency-key": key });
    await expect(client.health()).resolves.toEqual({ ok: true });
    expect(fetcher.mock.calls[1]?.[0]).toBe("https://relay.example/health");
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ method: "GET", credentials: "omit" });
  });

  it("parses relay batches and acknowledges delivered receipts", async () => {
    const receipt = new Uint8Array(16).fill(4);
    const payload = new Uint8Array(40 + 12 + 1024 + 16).fill(5);
    const batch = new Uint8Array(3 + 16 + 4 + payload.length);
    batch[0] = 1;
    new DataView(batch.buffer).setUint16(1, 1);
    batch.set(receipt, 3);
    new DataView(batch.buffer).setUint32(19, payload.length);
    batch.set(payload, 23);
    const responseSequence = [response(200, batch), response(204)];
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      const next = responseSequence.shift();
      if (!next) throw new Error("No mocked relay response remains.");
      return next;
    });
    const client = new RelayClient("https://relay.example", fetcher);

    await expect(client.read(queue)).resolves.toEqual([{ receipt, payload }]);
    await client.acknowledge(queue, [receipt]);
    const ack = fetcher.mock.calls[1]?.[1]?.body as Uint8Array;
    expect(ack.length).toBe(1 + 64 + 2 + 16);
    expect(new DataView(ack.buffer).getUint16(65)).toBe(1);
    expect(ack.slice(67)).toEqual(receipt);
  });

  it("rejects relay URLs with credentials and non-local cleartext transport", () => {
    expect(() => new RelayClient("https://user:secret@relay.example")).toThrow("must be an origin");
    expect(() => new RelayClient("http://relay.example")).toThrow("must use HTTPS");
    expect(() => new RelayClient("https://relay.example/prefix")).toThrow("must be an origin");
  });
});
