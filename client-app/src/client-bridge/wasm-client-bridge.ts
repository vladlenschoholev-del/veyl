import {
  EncryptedIndexedDbStorage,
  type PendingOutboxWrite,
} from "../storage-adapter/encrypted-storage";
import { RelayClient, type RelayQueue } from "./relayClient";
import {
  loadCryptoWasm,
  type CryptoWasmApi,
  type WasmProfileHandle,
  type WasmSessionHandle,
} from "./wasm-runtime";

type CryptoWasmModule = CryptoWasmApi;

const INVITE_MAGIC = new TextEncoder().encode("USTOYI1\0");
const REPLY_MAGIC = new TextEncoder().encode("USTOYR1\0");
const QUEUE_ACCESS_SIZE = 64;
const OFFER_SIZE = 1217;
const RESPONSE_SIZE = 1121;

export type MessageContent =
  | { kind: "text"; text: string }
  | { kind: "image"; name: string; mimeType: "image/jpeg" | "image/png"; bytes: string };

export interface LiveMessage {
  id: string;
  direction: "incoming" | "outgoing";
  content: MessageContent;
  delivery: "encrypted" | "pending" | "queued";
  sentAt: string;
}

export interface LiveChat {
  id: string;
  name: string;
  sas: string;
  verified: boolean;
  messages: LiveMessage[];
}

export interface LiveRelayConfig {
  incoming: string;
  outgoing: string;
}

interface ChatSession {
  chat: LiveChat;
  session: WasmSessionHandle;
  receiveQueue: RelayQueue;
  sendQueue?: Pick<RelayQueue, "id" | "writeCapability">;
  processedReceipts: Set<string>;
}

interface PendingInvitation {
  name: string;
  initiator: InstanceType<CryptoWasmModule["WasmInitiator"]>;
  receiveQueue: RelayQueue;
}

interface PersistedChat {
  chat: LiveChat;
  receiveQueue: { id: string; writeCapability: string; readCapability: string };
  sendQueue: { id: string; writeCapability: string } | null;
  processedReceipts: string[];
}

interface OutboxRecord {
  version: 1;
  chatId: string;
  messageId: string;
  relayUrl: string;
  idempotencyKey: string;
  queue: { id: string; writeCapability: string };
  encryptedPayload: string;
}

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (value.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invitation encoding is invalid.");
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  let decoded: string;
  try {
    decoded = atob(padded);
  } catch {
    throw new Error("Invitation encoding is invalid.");
  }
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function parseLink(raw: string, expectedPrefix: string): Uint8Array {
  const value = raw.trim();
  if (!value.startsWith(expectedPrefix)) throw new Error("Invitation link type is invalid.");
  return decodeBase64Url(value.slice(expectedPrefix.length));
}

function assertPrefix(bytes: Uint8Array, magic: Uint8Array): number {
  if (bytes.length < magic.length || magic.some((byte, index) => bytes[index] !== byte)) {
    throw new Error("Invitation packet version is unsupported.");
  }
  return magic.length;
}

function queueAccess(queue: Pick<RelayQueue, "id" | "writeCapability">): Uint8Array {
  if (queue.id.length !== 32 || queue.writeCapability.length !== 32) {
    throw new Error("Malformed queue write capability.");
  }
  const encoded = new Uint8Array(QUEUE_ACCESS_SIZE);
  encoded.set(queue.id);
  encoded.set(queue.writeCapability, 32);
  return encoded;
}

function parseQueueAccess(bytes: Uint8Array): Pick<RelayQueue, "id" | "writeCapability"> {
  if (bytes.length !== QUEUE_ACCESS_SIZE) throw new Error("Malformed queue write capability.");
  return { id: bytes.slice(0, 32), writeCapability: bytes.slice(32) };
}

function parseBase64(value: string): Uint8Array {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  return encodeBase64Url(bytes);
}

export class WasmClientBridge {
  private readonly chats = new Map<string, ChatSession>();
  private readonly pendingInvitations = new Map<string, PendingInvitation>();
  private readonly relayClients = new Map<string, RelayClient>();
  private retrying?: Promise<{ sent: number; failed: number; error?: string }>;

  constructor(
    private readonly storage: EncryptedIndexedDbStorage,
    private readonly profile: WasmProfileHandle,
    private relayConfig: LiveRelayConfig,
    private readonly profileNamespace: "real" | "decoy" = "real",
  ) {}

  async createInvitation(name: string): Promise<{ chatId: string; link: string }> {
    const cryptoWasm = await loadCryptoWasm();
    const receiveQueue = await this.relay(this.relayConfig.incoming).createQueue();
    const initiator = new cryptoWasm.WasmInitiator();
    const publicOffer = initiator.publicBytes();
    const chatId = randomId();
    const encoded = new Uint8Array(INVITE_MAGIC.length + QUEUE_ACCESS_SIZE + publicOffer.length);
    encoded.set(INVITE_MAGIC);
    encoded.set(queueAccess(receiveQueue), INVITE_MAGIC.length);
    encoded.set(publicOffer, INVITE_MAGIC.length + QUEUE_ACCESS_SIZE);
    this.pendingInvitations.set(chatId, {
      name: name.trim() || "Новый контакт",
      initiator,
      receiveQueue,
    });
    return { chatId, link: `ustoy://invite/${encodeBase64Url(encoded)}` };
  }

  async acceptInvitation(
    raw: string,
    name: string,
  ): Promise<{ chatId: string; replyLink: string; sas: string }> {
    const encoded = parseLink(raw, "ustoy://invite/");
    const offset = assertPrefix(encoded, INVITE_MAGIC);
    if (encoded.length !== offset + QUEUE_ACCESS_SIZE + OFFER_SIZE) {
      throw new Error("Invitation has an invalid length.");
    }
    await this.storage.claimOneTimeInvitation(encoded);
    const targetQueue = parseQueueAccess(encoded.slice(offset, offset + QUEUE_ACCESS_SIZE));
    const offer = encoded.slice(offset + QUEUE_ACCESS_SIZE);
    const receiveQueue = await this.relay(this.relayConfig.incoming).createQueue();
    const cryptoWasm = await loadCryptoWasm();
    const responder = cryptoWasm.create_responder(offer);
    const response = responder.responseBytes();
    let session: WasmSessionHandle;
    try {
      session = responder.takeSession();
    } finally {
      responder.free();
    }
    const sas = session.sas();
    if (!sas) {
      session.free();
      throw new Error("Handshake did not produce an authentication code.");
    }

    const reply = new Uint8Array(
      REPLY_MAGIC.length + QUEUE_ACCESS_SIZE + QUEUE_ACCESS_SIZE + response.length,
    );
    reply.set(REPLY_MAGIC);
    reply.set(queueAccess(targetQueue), REPLY_MAGIC.length);
    reply.set(queueAccess(receiveQueue), REPLY_MAGIC.length + QUEUE_ACCESS_SIZE);
    reply.set(response, REPLY_MAGIC.length + 2 * QUEUE_ACCESS_SIZE);
    const chatId = randomId();
    const chat: LiveChat = {
      id: chatId,
      name: name.trim() || "Новый контакт",
      sas,
      verified: false,
      messages: [],
    };
    const item = {
      chat,
      session,
      receiveQueue,
      sendQueue: targetQueue,
      processedReceipts: new Set<string>(),
    };
    this.chats.set(chatId, item);
    await this.persistState(item);
    return { chatId, replyLink: `ustoy://reply/${encodeBase64Url(reply)}`, sas };
  }

  async completeInvitation(chatId: string, rawReply: string): Promise<LiveChat> {
    const pending = this.pendingInvitations.get(chatId);
    if (!pending) throw new Error("No matching one-time invitation is pending.");
    const encoded = parseLink(rawReply, "ustoy://reply/");
    const offset = assertPrefix(encoded, REPLY_MAGIC);
    if (encoded.length !== offset + 2 * QUEUE_ACCESS_SIZE + RESPONSE_SIZE) {
      throw new Error("Handshake reply has an invalid length.");
    }
    const invitedQueue = parseQueueAccess(encoded.slice(offset, offset + QUEUE_ACCESS_SIZE));
    if (
      invitedQueue.id.some((byte, index) => byte !== pending.receiveQueue.id[index]) ||
      invitedQueue.writeCapability.some(
        (byte, index) => byte !== pending.receiveQueue.writeCapability[index],
      )
    ) {
      throw new Error("Handshake reply does not match the pending invitation.");
    }
    const targetQueue = parseQueueAccess(encoded.slice(offset + QUEUE_ACCESS_SIZE, offset + 2 * QUEUE_ACCESS_SIZE));
    const response = encoded.slice(offset + 2 * QUEUE_ACCESS_SIZE);
    this.pendingInvitations.delete(chatId);
    let session: WasmSessionHandle;
    try {
      session = pending.initiator.finish(response);
    } finally {
      pending.initiator.free();
    }
    const sas = session.sas();
    if (!sas) {
      session.free();
      throw new Error("Handshake did not produce an authentication code.");
    }
    const item: ChatSession = {
      chat: {
        id: chatId,
        name: pending.name,
        sas,
        verified: false,
        messages: [],
      },
      session,
      receiveQueue: pending.receiveQueue,
      sendQueue: targetQueue,
      processedReceipts: new Set<string>(),
    };
    this.chats.set(chatId, item);
    await this.persistState(item);
    return item.chat;
  }

  async confirmSas(chatId: string, sas: string): Promise<void> {
    const item = this.requireChat(chatId);
    item.session.confirmSas(sas);
    item.chat = { ...item.chat, verified: true };
    await this.persistState(item);
  }

  async sendText(chatId: string, text: string): Promise<void> {
    const item = this.requireVerifiedChat(chatId);
    const cleanText = text.trim();
    if (!cleanText) return;
    await this.sendContent(item, { kind: "text", text: cleanText });
  }

  async sendImage(chatId: string, file: File): Promise<void> {
    const item = this.requireVerifiedChat(chatId);
    if (file.type !== "image/jpeg" && file.type !== "image/png") {
      throw new Error("Only JPEG and PNG images are supported; audio and documents are rejected.");
    }
    const cryptoWasm = await loadCryptoWasm();
    const cleanBytes = cryptoWasm.sanitize_image(new Uint8Array(await file.arrayBuffer()));
    const mimeType =
      cleanBytes[0] === 0xff && cleanBytes[1] === 0xd8
        ? "image/jpeg"
        : cleanBytes[0] === 0x89 && cleanBytes[1] === 0x50
          ? "image/png"
          : null;
    if (!mimeType) throw new Error("Image sanitizer returned an unsupported image.");
    await this.sendContent(item, {
      kind: "image",
      name: file.name,
      mimeType,
      bytes: toBase64(cleanBytes),
    });
  }

  async poll(chatId: string): Promise<LiveMessage[]> {
    const item = this.requireChat(chatId);
    const messages = await this.relay(this.relayConfig.incoming).read(item.receiveQueue);
    const cryptoWasm = await loadCryptoWasm();
    for (const relayed of messages) {
      const receiptId = encodeBase64Url(relayed.receipt);
      if (item.processedReceipts.has(receiptId)) {
        await this.relay(this.relayConfig.incoming).acknowledge(item.receiveQueue, [relayed.receipt]);
        item.processedReceipts.delete(receiptId);
        await this.persistState(item);
        continue;
      }
      const plaintext = cryptoWasm.unpad_payload(item.session.decrypt(relayed.payload));
      const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as MessageContent;
      if (
        (parsed.kind !== "text" && parsed.kind !== "image") ||
        (parsed.kind === "text" && typeof parsed.text !== "string") ||
        (parsed.kind === "image" &&
          (parsed.mimeType !== "image/jpeg" && parsed.mimeType !== "image/png" ||
            typeof parsed.bytes !== "string" ||
            typeof parsed.name !== "string"))
      ) {
        throw new Error("Received message content is invalid.");
      }
      item.chat = {
        ...item.chat,
        messages: [
          ...item.chat.messages,
          {
            id: randomId(),
            direction: "incoming",
            content: parsed,
            delivery: "queued",
            sentAt: new Date().toISOString(),
          },
        ],
      };
      item.processedReceipts.add(receiptId);
      await this.persistState(item);
      await this.relay(this.relayConfig.incoming).acknowledge(item.receiveQueue, [relayed.receipt]);
      item.processedReceipts.delete(receiptId);
      await this.persistState(item);
    }
    return item.chat.messages;
  }

  setRelayConfig(config: LiveRelayConfig): void {
    this.relayConfig = config;
  }

  retryOutbox(): Promise<{ sent: number; failed: number; error?: string }> {
    if (!this.retrying) {
      this.retrying = this.flushOutbox().finally(() => {
        this.retrying = undefined;
      });
    }
    return this.retrying;
  }

  getChat(chatId: string): LiveChat {
    return this.requireChat(chatId).chat;
  }

  listChats(): LiveChat[] {
    return [...this.chats.values()].map((item) => item.chat);
  }

  lock(): void {
    for (const item of this.chats.values()) item.session.free();
    for (const invitation of this.pendingInvitations.values()) invitation.initiator.free();
    this.chats.clear();
    this.pendingInvitations.clear();
  }

  private async sendContent(item: ChatSession, content: MessageContent): Promise<void> {
    if (!item.sendQueue) throw new Error("Handshake reply has not been exchanged yet.");
    const cryptoWasm = await loadCryptoWasm();
    const previousSnapshot = this.profile.serializeSession(item.session);
    const previousChat = item.chat;
    const plaintext = new TextEncoder().encode(JSON.stringify(content));
    const padded = cryptoWasm.pad_payload(plaintext);
    let encryptedPayload: Uint8Array;
    try {
      encryptedPayload = item.session.encrypt(padded);
    } catch (error) {
      item.session.free();
      item.session = this.profile.restoreSession(previousSnapshot);
      throw error;
    }
    const messageId = randomId();
    const outboxId = randomId();
    const outbox: OutboxRecord = {
      version: 1,
      chatId: item.chat.id,
      messageId,
      relayUrl: this.relayConfig.outgoing,
      idempotencyKey: outboxId,
      queue: {
        id: toBase64(item.sendQueue.id),
        writeCapability: toBase64(item.sendQueue.writeCapability),
      },
      encryptedPayload: toBase64(encryptedPayload),
    };
    item.chat = {
      ...item.chat,
      messages: [
        ...item.chat.messages,
        {
          id: messageId,
          direction: "outgoing",
          content,
          delivery: "pending",
          sentAt: new Date().toISOString(),
        },
      ],
    };
    const outboxWrite: PendingOutboxWrite = {
      id: outboxId,
      namespace: this.profileNamespace,
      plaintext: new TextEncoder().encode(JSON.stringify(outbox)),
    };
    try {
      await this.persistState(item, outboxWrite);
    } catch (error) {
      item.session.free();
      item.session = this.profile.restoreSession(previousSnapshot);
      item.chat = previousChat;
      throw error;
    }
    await this.retryOutbox();
  }

  private requireChat(chatId: string): ChatSession {
    const item = this.chats.get(chatId);
    if (!item) throw new Error("Chat session is unavailable.");
    return item;
  }

  private requireVerifiedChat(chatId: string): ChatSession {
    const item = this.requireChat(chatId);
    if (!item.chat.verified) throw new Error("Verify the 48-bit SAS before sending messages.");
    return item;
  }

  private relay(url: string): RelayClient {
    let client = this.relayClients.get(url);
    if (!client) {
      client = new RelayClient(url);
      this.relayClients.set(url, client);
    }
    return client;
  }

  private async persistState(
    item: ChatSession,
    outboxWrite?: PendingOutboxWrite,
  ): Promise<void> {
    const indexRecord = await this.storage.openRecord(this.profile, this.chatIndexId());
    const chatIds = indexRecord
      ? (JSON.parse(new TextDecoder().decode(indexRecord)) as string[])
      : [];
    if (!chatIds.includes(item.chat.id)) {
      chatIds.push(item.chat.id);
      await this.storage.sealRecord(
        this.profile,
        this.chatIndexId(),
        new TextEncoder().encode(JSON.stringify(chatIds)),
      );
    }
    const snapshot = this.profile.serializeSession(item.session);
    await this.storage.saveEncryptedChatState(
      this.profile,
      this.scopedChatId(item.chat.id),
      this.encodePersistedChat(item),
      snapshot,
      outboxWrite,
    );
  }

  private async flushOutbox(): Promise<{ sent: number; failed: number; error?: string }> {
    const entries = await this.storage.listOutbox(this.profile, this.profileNamespace);
    let sent = 0;
    for (const entry of entries) {
      const outbox = this.decodeOutbox(entry.plaintext);
      try {
        const client = this.relay(outbox.relayUrl);
        await client.send(
          {
            id: parseBase64(outbox.queue.id),
            writeCapability: parseBase64(outbox.queue.writeCapability),
          },
          parseBase64(outbox.encryptedPayload),
          outbox.idempotencyKey,
        );
        const chatSession = this.chats.get(outbox.chatId);
        if (chatSession) {
          chatSession.chat = {
            ...chatSession.chat,
            messages: chatSession.chat.messages.map((message) =>
              message.id === outbox.messageId ? { ...message, delivery: "queued" } : message,
            ),
          };
          await this.persistState(chatSession);
        }
        await this.storage.deleteOutbox(this.profileNamespace, entry.id);
        sent += 1;
      } catch (error) {
        return {
          sent,
          failed: entries.length - sent,
          error: error instanceof Error ? error.message : "Outbox retry failed.",
        };
      }
    }
    return { sent, failed: 0 };
  }

  private decodeOutbox(encoded: Uint8Array): OutboxRecord {
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
    } catch {
      throw new Error("Encrypted outbox entry is not valid JSON.");
    }
    if (!value || typeof value !== "object") throw new Error("Encrypted outbox entry is malformed.");
    const record = value as Partial<OutboxRecord>;
    if (
      record.version !== 1 ||
      typeof record.chatId !== "string" ||
      typeof record.messageId !== "string" ||
      typeof record.relayUrl !== "string" ||
      typeof record.idempotencyKey !== "string" ||
      !/^[0-9a-f]{32}$/i.test(record.idempotencyKey) ||
      typeof record.encryptedPayload !== "string" ||
      !record.queue ||
      typeof record.queue.id !== "string" ||
      typeof record.queue.writeCapability !== "string"
    ) {
      throw new Error("Encrypted outbox entry is malformed.");
    }
    return record as OutboxRecord;
  }

  private encodePersistedChat(item: ChatSession): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({
      chat: item.chat,
      receiveQueue: {
        id: toBase64(item.receiveQueue.id),
        writeCapability: toBase64(item.receiveQueue.writeCapability),
        readCapability: toBase64(item.receiveQueue.readCapability),
      },
      sendQueue: item.sendQueue
        ? { id: toBase64(item.sendQueue.id), writeCapability: toBase64(item.sendQueue.writeCapability) }
        : null,
      processedReceipts: [...item.processedReceipts],
    }));
  }

  async restoreChats(): Promise<LiveChat[]> {
    const encodedIndex = await this.storage.openRecord(this.profile, this.chatIndexId());
    if (!encodedIndex) return [];
    const chatIds = JSON.parse(new TextDecoder().decode(encodedIndex)) as string[];
    if (!Array.isArray(chatIds) || chatIds.some((id) => typeof id !== "string")) {
      throw new Error("Encrypted chat index is malformed.");
    }
    const restored: LiveChat[] = [];
    for (const chatId of chatIds) {
      const [encoded, snapshot] = await Promise.all([
        this.storage.openRecord(this.profile, this.chatRecordId(chatId)),
        this.storage.readSessionSnapshot(this.scopedChatId(chatId)),
      ]);
      if (!encoded || !snapshot) throw new Error(`Persisted chat ${chatId} is incomplete.`);
      const persisted = JSON.parse(new TextDecoder().decode(encoded)) as PersistedChat;
      const receiveQueue: RelayQueue = {
        id: parseBase64(persisted.receiveQueue.id),
        writeCapability: parseBase64(persisted.receiveQueue.writeCapability),
        readCapability: parseBase64(persisted.receiveQueue.readCapability),
      };
      const session = this.profile.restoreSession(snapshot);
      if (
        session.verificationStatus() !==
        (persisted.chat.verified ? "VERIFIED" : "UNVERIFIED")
      ) {
        throw new Error(`Persisted verification state for chat ${chatId} is inconsistent.`);
      }
      const item: ChatSession = {
        chat: persisted.chat,
        session,
        receiveQueue,
        sendQueue: persisted.sendQueue
          ? {
              id: parseBase64(persisted.sendQueue.id),
              writeCapability: parseBase64(persisted.sendQueue.writeCapability),
            }
          : undefined,
        processedReceipts: new Set(persisted.processedReceipts),
      };
      this.chats.set(chatId, item);
      restored.push(item.chat);
    }
    return restored;
  }

  private chatRecordId(chatId: string): string {
    return `chat:${this.profileNamespace}:${chatId}`;
  }

  private chatIndexId(): string {
    return `system:${this.profileNamespace}:chat-index`;
  }

  private scopedChatId(chatId: string): string {
    return `${this.profileNamespace}:${chatId}`;
  }

}
