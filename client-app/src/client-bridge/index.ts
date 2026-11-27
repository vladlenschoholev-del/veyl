import {
  IndexedDbKeyWrapStorage,
  type DemoStorageInspection,
  type PersistentDuressState,
} from "../storage-adapter/key-wrap-storage";
import { sanitizeImageForDemo, type SanitizedImage } from "./media";

export type DeliveryState = "encrypted" | "queued" | "acknowledged";
export type ProfileMode = "real" | "pending" | "decoy";

export interface ChatMessage {
  id: string;
  body: string;
  direction: "incoming" | "outgoing";
  delivery: DeliveryState;
  sentAt: string;
  attachment?: {
    name: string;
    mimeType: string;
    previewUrl: string;
    size: number;
  };
}

export interface Chat {
  id: string;
  name: string;
  sasHex: string;
  verified: boolean;
  messages: ChatMessage[];
}

export interface DemoInvitation {
  chatId: string;
  queueId: string;
  readCapability: string;
  writeCapability: string;
  sasHex: string;
  link: string;
}

export interface RelayConfig {
  incoming: string;
  outgoing: string;
}

export interface DemoClientState {
  chats: Chat[];
  activeChatId: string | null;
  profileMode: ProfileMode;
  duressState: PersistentDuressState;
  storageReady: boolean;
  storageError: string | null;
  storageInspection: DemoStorageInspection | null;
  relayConfig: RelayConfig;
  invitation: DemoInvitation | null;
}

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function makeChat(
  name: string,
  sasHex: string,
  verified: boolean,
  messages: ChatMessage[] = [],
  id = randomHex(8),
): Chat {
  return { id, name, sasHex, verified, messages };
}

function createSeedChats(): Chat[] {
  const now = Date.now();
  return [
    makeChat(
      "Марта",
      "A17C3095B42E",
      true,
      [
        {
          id: "seed-1",
          body: "Проверила маршрут. Всё спокойно.",
          direction: "incoming",
          delivery: "acknowledged",
          sentAt: new Date(now - 1000 * 60 * 38).toISOString(),
        },
        {
          id: "seed-2",
          body: "Хорошо. Увидимся у старого моста после шести.",
          direction: "outgoing",
          delivery: "acknowledged",
          sentAt: new Date(now - 1000 * 60 * 33).toISOString(),
        },
        {
          id: "seed-3",
          body: "Договорились 🌿",
          direction: "incoming",
          delivery: "acknowledged",
          sentAt: new Date(now - 1000 * 60 * 31).toISOString(),
        },
      ],
      "chat-marta",
    ),
    makeChat(
      "Лев",
      "51E208A3C79D",
      false,
      [
        {
          id: "seed-4",
          body: "Привет! Отправил тебе приглашение.",
          direction: "incoming",
          delivery: "acknowledged",
          sentAt: new Date(now - 1000 * 60 * 60 * 3).toISOString(),
        },
      ],
      "chat-lev",
    ),
    makeChat(
      "Соня",
      "8C0D46F12A73",
      true,
      [
        {
          id: "seed-5",
          body: "Спасибо, получила.",
          direction: "incoming",
          delivery: "acknowledged",
          sentAt: new Date(now - 1000 * 60 * 60 * 24).toISOString(),
        },
      ],
      "chat-sonya",
    ),
  ];
}

function createDecoyChats(): Chat[] {
  return [
    makeChat(
      "Заметки",
      "000000000000",
      false,
      [
        {
          id: "decoy-note-1",
          body: "Купить чай и проверить список дел.",
          direction: "incoming",
          delivery: "acknowledged",
          sentAt: new Date().toISOString(),
        },
      ],
      "decoy-notes",
    ),
  ];
}

export class DemoClientBridge {
  private readonly listeners = new Set<() => void>();
  private state: DemoClientState = {
    chats: [],
    activeChatId: null,
    profileMode: "pending",
    duressState: "NORMAL",
    storageReady: false,
    storageError: null,
    storageInspection: null,
    relayConfig: {
      incoming: "https://relay-in.example.invalid",
      outgoing: "https://relay-out.example.invalid",
    },
    invitation: null,
  };
  private startPromise: Promise<void> | null = null;

  constructor(
    private readonly storage: IndexedDbKeyWrapStorage = new IndexedDbKeyWrapStorage(),
    private readonly imageSanitizer: (file: File) => Promise<SanitizedImage> =
      sanitizeImageForDemo,
  ) {}

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getSnapshot = (): DemoClientState => this.state;

  start(): Promise<void> {
    this.startPromise ??= this.initialize();
    return this.startPromise;
  }

  private async initialize(): Promise<void> {
    try {
      await this.storage.ensureDemoState();
      const duressState = await this.storage.duressState();
      if (duressState === "ACTIVE") {
        this.applyDecoyProfile();
      } else if (duressState === "DURESS_PENDING_CLEANUP") {
        this.update({
          profileMode: "pending",
          duressState,
          chats: [],
          activeChatId: null,
        });
        await this.retryDuressCleanup();
      } else {
        this.update({
          profileMode: "real",
          chats: createSeedChats(),
          activeChatId: "chat-marta",
        });
      }
      const storageInspection = await this.storage.inspectDemoState();
      this.update({
        storageReady: true,
        storageError: null,
        storageInspection,
        duressState: await this.storage.duressState(),
      });
    } catch (error) {
      this.update({
        storageReady: true,
        storageError: this.messageFor(error),
      });
    }
  }

  setActiveChat(chatId: string): void {
    if (!this.state.chats.some((chat) => chat.id === chatId)) return;
    this.update({ activeChatId: chatId });
  }

  createChat(name: string): Chat {
    const chat = makeChat(name.trim() || "Новый контакт", randomHex(6).toUpperCase(), false);
    this.update({
      chats: [chat, ...this.state.chats],
      activeChatId: chat.id,
      invitation: null,
    });
    return chat;
  }

  createInvitation(chatId: string): DemoInvitation {
    const chat = this.state.chats.find((item) => item.id === chatId);
    if (!chat) throw new Error("Сначала выберите или создайте чат.");
    const queueId = randomHex(16);
    const readCapability = randomHex(32);
    const writeCapability = randomHex(32);
    const link = `ustoy-demo://invite?queue=${queueId}&read=${readCapability}&write=${writeCapability}&sas=${chat.sasHex}`;
    const invitation = {
      chatId,
      queueId,
      readCapability,
      writeCapability,
      sasHex: chat.sasHex,
      link,
    };
    this.update({ invitation });
    return invitation;
  }

  importInvitation(raw: string, contactName: string): Chat {
    let url: URL;
    try {
      url = new URL(raw.trim());
    } catch {
      throw new Error("Ссылка приглашения имеет неверный формат.");
    }
    if (
      url.protocol !== "ustoy-demo:" ||
      url.hostname !== "invite" ||
      !url.searchParams.get("queue") ||
      !url.searchParams.get("read") ||
      !url.searchParams.get("write")
    ) {
      throw new Error("Это не приглашение демо-формата Устой.");
    }
    const sasHex = url.searchParams.get("sas")?.toUpperCase() ?? "";
    if (!/^[0-9A-F]{12}$/.test(sasHex)) {
      throw new Error("В приглашении отсутствует корректный демо-SAS.");
    }
    const chat = makeChat(contactName.trim() || "Новый контакт", sasHex, false);
    this.update({
      chats: [chat, ...this.state.chats],
      activeChatId: chat.id,
      invitation: null,
    });
    return chat;
  }

  confirmSas(chatId: string): void {
    this.update({
      chats: this.state.chats.map((chat) =>
        chat.id === chatId ? { ...chat, verified: true } : chat,
      ),
    });
  }

  setRelayConfig(relayConfig: RelayConfig): void {
    this.update({ relayConfig });
  }

  async sendText(chatId: string, body: string): Promise<void> {
    const text = body.trim();
    if (!text) return;
    const message = this.appendMessage(chatId, {
      body: text,
      direction: "outgoing",
      delivery: "encrypted",
      sentAt: new Date().toISOString(),
    });
    this.scheduleDelivery(chatId, message.id);
  }

  async sendImage(chatId: string, file: File): Promise<void> {
    const cleanImage = await this.imageSanitizer(file);
    const message = this.appendMessage(chatId, {
      body: "",
      direction: "outgoing",
      delivery: "encrypted",
      sentAt: new Date().toISOString(),
      attachment: {
        name: cleanImage.file.name,
        mimeType: cleanImage.mimeType,
        previewUrl: cleanImage.previewUrl,
        size: cleanImage.file.size,
      },
    });
    this.scheduleDelivery(chatId, message.id);
  }

  async activateDuress(simulateDeletionFailure: boolean): Promise<void> {
    if (simulateDeletionFailure) this.storage.failNextDeleteForDemo();

    this.update({
      profileMode: "pending",
      duressState: "DURESS_PENDING_CLEANUP",
      chats: [],
      activeChatId: null,
      invitation: null,
    });
    await this.storage.markDuressPendingCleanup();
    const receipt = await this.storage.deleteRealKeyWrap();
    await this.storage.markDuressActive(receipt);
    this.applyDecoyProfile();
    await this.refreshStorageInspection();
  }

  async retryDuressCleanup(): Promise<void> {
    const currentState = await this.storage.duressState();
    if (currentState === "ACTIVE") {
      this.applyDecoyProfile();
      await this.refreshStorageInspection();
      return;
    }
    if (currentState !== "DURESS_PENDING_CLEANUP") {
      throw new Error("Нет незавершённой очистки duress для повтора.");
    }
    this.update({
      profileMode: "pending",
      duressState: currentState,
      chats: [],
      activeChatId: null,
    });
    const receipt = await this.storage.deleteRealKeyWrap();
    await this.storage.markDuressActive(receipt);
    this.applyDecoyProfile();
    await this.refreshStorageInspection();
  }

  async refreshStorageInspection(): Promise<void> {
    const storageInspection = await this.storage.inspectDemoState();
    this.update({
      storageInspection,
      duressState:
        this.state.profileMode === "pending" &&
        storageInspection.state === "NORMAL"
          ? this.state.duressState
          : storageInspection.state,
    });
  }

  private appendMessage(
    chatId: string,
    message: Omit<ChatMessage, "id">,
  ): ChatMessage {
    const chat = this.state.chats.find((item) => item.id === chatId);
    if (!chat) throw new Error("Активный чат недоступен.");
    const completeMessage = { ...message, id: randomHex(8) };
    this.update({
      chats: this.state.chats.map((item) =>
        item.id === chatId
          ? { ...item, messages: [...item.messages, completeMessage] }
          : item,
      ),
    });
    return completeMessage;
  }

  private scheduleDelivery(chatId: string, messageId: string): void {
    window.setTimeout(() => this.setDelivery(chatId, messageId, "queued"), 550);
    window.setTimeout(
      () => this.setDelivery(chatId, messageId, "acknowledged"),
      1250,
    );
  }

  private setDelivery(
    chatId: string,
    messageId: string,
    delivery: DeliveryState,
  ): void {
    this.update({
      chats: this.state.chats.map((chat) =>
        chat.id === chatId
          ? {
              ...chat,
              messages: chat.messages.map((message) =>
                message.id === messageId ? { ...message, delivery } : message,
              ),
            }
          : chat,
      ),
    });
  }

  private applyDecoyProfile(): void {
    const chats = createDecoyChats();
    this.update({
      profileMode: "decoy",
      duressState: "ACTIVE",
      chats,
      activeChatId: chats[0]?.id ?? null,
      invitation: null,
    });
  }

  private update(patch: Partial<DemoClientState>): void {
    this.state = { ...this.state, ...patch };
    for (const listener of this.listeners) listener();
  }

  private messageFor(error: unknown): string {
    return error instanceof Error ? error.message : "Не удалось выполнить операцию.";
  }
}

export { WasmClientBridge } from "./wasm-client-bridge";
export type {
  LiveChat,
  LiveMessage,
  LiveRelayConfig,
  MessageContent,
} from "./wasm-client-bridge";
export { RelayClient } from "./relayClient";
export type { RelayQueue, RelayedMessage } from "./relayClient";
