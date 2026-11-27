import {
  loadCryptoWasm,
  type WasmProfileHandle,
} from "../client-bridge/wasm-runtime";

export type DuressStorageState = "NORMAL" | "DURESS_PENDING_CLEANUP" | "ACTIVE";

const DATABASE_NAME = "ustoy-client";
const DATABASE_VERSION = 4;
const METADATA_STORE = "metadata";
const KEY_WRAP_STORE = "key-wraps";
const RECORD_STORE = "encrypted-records";
const SESSION_STORE = "encrypted-sessions";
const USED_INVITATION_STORE = "used-invitations";
const OUTBOX_STORE = "encrypted-outbox";
const BACKUP_MAGIC = new TextEncoder().encode("USTOYF1\0");
const BACKUP_STORES = [
  METADATA_STORE,
  KEY_WRAP_STORE,
  RECORD_STORE,
  SESSION_STORE,
  USED_INVITATION_STORE,
  OUTBOX_STORE,
] as const;
const MAX_BACKUP_SIZE = 128 * 1024 * 1024;
const REAL_WRAP_KEY = "real";
const DECOY_WRAP_KEY = "decoy";
const DURESS_STATE_KEY = "duress-state";
const PROFILE_INITIALIZED_KEY = "profile-initialized";
const receiptBrand: unique symbol = Symbol("durable-key-wrap-deletion-receipt");

export type DeletionReceipt = Readonly<{
  confirmed: true;
  [receiptBrand]: true;
}>;

export interface PendingOutboxWrite {
  id: string;
  namespace: "real" | "decoy";
  plaintext: Uint8Array;
}

interface BackupEntry {
  key: string;
  kind: "bytes" | "string" | "boolean";
  value: string | boolean;
}

interface BackupContainer {
  version: 1;
  stores: Record<string, BackupEntry[]>;
}

export interface EncryptedRecord {
  id: string;
  ciphertext: Uint8Array;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

function transactionCompletion(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed."));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted."));
  });
}

function bytes(value: Uint8Array | ArrayBuffer): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function encodeBytes(value: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function decodeBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function recordBindingKey(id: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(id));
  return new Uint8Array(digest);
}

export class EncryptedIndexedDbStorage {
  private readonly database: Promise<IDBDatabase>;

  constructor() {
    if (!("indexedDB" in globalThis)) throw new Error("IndexedDB is unavailable.");
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(METADATA_STORE)) db.createObjectStore(METADATA_STORE);
        if (!db.objectStoreNames.contains(KEY_WRAP_STORE)) db.createObjectStore(KEY_WRAP_STORE);
        if (!db.objectStoreNames.contains(RECORD_STORE)) db.createObjectStore(RECORD_STORE);
        if (!db.objectStoreNames.contains(SESSION_STORE)) db.createObjectStore(SESSION_STORE);
        if (!db.objectStoreNames.contains(USED_INVITATION_STORE)) {
          db.createObjectStore(USED_INVITATION_STORE);
        }
        if (!db.objectStoreNames.contains(OUTBOX_STORE)) db.createObjectStore(OUTBOX_STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Unable to open IndexedDB."));
      request.onblocked = () => reject(new Error("IndexedDB upgrade is blocked."));
    });
  }

  async initializeProfile(primaryPin: string, duressPin: string): Promise<void> {
    const crypto = await loadCryptoWasm();
    const profile = new crypto.WasmProfile(primaryPin, duressPin);
    try {
      const transaction = (await this.database).transaction(
        [METADATA_STORE, KEY_WRAP_STORE],
        "readwrite",
      );
      const completion = transactionCompletion(transaction);
      const metadata = transaction.objectStore(METADATA_STORE);
      const wraps = transaction.objectStore(KEY_WRAP_STORE);
      const initialized = metadata.get(PROFILE_INITIALIZED_KEY);
      initialized.onsuccess = () => {
        if (initialized.result === true) {
          transaction.abort();
          return;
        }
        metadata.put(true, PROFILE_INITIALIZED_KEY);
        metadata.put("NORMAL", DURESS_STATE_KEY);
        wraps.put(profile.realKeyWrap(), REAL_WRAP_KEY);
        wraps.put(profile.decoyKeyWrap(), DECOY_WRAP_KEY);
      };
      await completion;
    } finally {
      profile.free();
    }
  }

  async isProfileInitialized(): Promise<boolean> {
    return (await this.readMetadata(PROFILE_INITIALIZED_KEY)) === true;
  }

  async duressState(): Promise<DuressStorageState> {
    const state = await this.readMetadata(DURESS_STATE_KEY);
    if (state === "NORMAL" || state === "DURESS_PENDING_CLEANUP" || state === "ACTIVE") {
      return state;
    }
    throw new Error("Persistent duress state is missing or malformed.");
  }

  async recoverPendingDuress(): Promise<void> {
    if ((await this.duressState()) !== "DURESS_PENDING_CLEANUP") return;
    await this.deleteRealKeyWrap();
    await this.writeDuressState("ACTIVE");
  }

  async unlock(pin: string): Promise<{ profile: WasmProfileHandle; mode: string }> {
    if ((await this.readMetadata(PROFILE_INITIALIZED_KEY)) !== true) {
      throw new Error("Profile has not been initialized.");
    }
    await this.recoverPendingDuress();
    const [state, realWrap, decoyWrap] = await Promise.all([
      this.duressState(),
      this.readWrap(REAL_WRAP_KEY),
      this.readWrap(DECOY_WRAP_KEY),
    ]);
    if (!decoyWrap) throw new Error("Decoy key wrapper is missing.");
    if (state === "NORMAL" && !realWrap) throw new Error("Real key wrapper is missing.");

    const crypto = await loadCryptoWasm();
    const profile = crypto.WasmProfile.fromStoredWraps(
      realWrap ?? new Uint8Array(),
      decoyWrap,
      state,
    );
    try {
      const mode = profile.unlockWithPin(pin);
      if (mode === "DURESS_PENDING_CLEANUP") {
        await this.writeDuressState("DURESS_PENDING_CLEANUP");
        const receipt = await this.deleteRealKeyWrap();
        await this.markDuressActive(receipt);
        profile.activateDecoyAfterCleanup();
        return { profile, mode: "DECOY" };
      }
      return { profile, mode };
    } catch (error) {
      profile.free();
      throw error;
    }
  }

  async sealRecord(
    profile: WasmProfileHandle,
    id: string,
    plaintext: Uint8Array,
  ): Promise<void> {
    const recordId = await recordBindingKey(id);
    const ciphertext = profile.sealLocalRecord(recordId, plaintext);
    const transaction = (await this.database).transaction(RECORD_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(RECORD_STORE).put(ciphertext, id);
    await completion;
  }

  async saveEncryptedChatState(
    profile: WasmProfileHandle,
    chatId: string,
    plaintext: Uint8Array,
    encryptedSnapshot: Uint8Array,
    outboxWrite?: PendingOutboxWrite,
  ): Promise<void> {
    const recordId = `chat:${chatId}`;
    const ciphertext = profile.sealLocalRecord(
      await recordBindingKey(recordId),
      plaintext,
    );
    const outboxKey = outboxWrite
      ? `${outboxWrite.namespace}:${outboxWrite.id}`
      : undefined;
    const encryptedOutbox = outboxWrite
      ? profile.sealLocalRecord(
          await recordBindingKey(`outbox:${outboxKey}`),
          outboxWrite.plaintext,
        )
      : undefined;
    const transaction = (await this.database).transaction(
      outboxWrite ? [RECORD_STORE, SESSION_STORE, OUTBOX_STORE] : [RECORD_STORE, SESSION_STORE],
      "readwrite",
    );
    const completion = transactionCompletion(transaction);
    transaction.objectStore(RECORD_STORE).put(ciphertext, recordId);
    transaction.objectStore(SESSION_STORE).put(encryptedSnapshot, chatId);
    if (outboxKey && encryptedOutbox) {
      transaction.objectStore(OUTBOX_STORE).put(encryptedOutbox, outboxKey);
    }
    await completion;
  }

  async listOutbox(
    profile: WasmProfileHandle,
    namespace: "real" | "decoy",
  ): Promise<Array<{ id: string; plaintext: Uint8Array }>> {
    const transaction = (await this.database).transaction(OUTBOX_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const store = transaction.objectStore(OUTBOX_STORE);
    const [keys, values] = await Promise.all([
      requestResult(store.getAllKeys()),
      requestResult(store.getAll()),
    ]);
    await completion;
    const prefix = `${namespace}:`;
    const records: Array<{ id: string; plaintext: Uint8Array }> = [];
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== "string" || !key.startsWith(prefix)) continue;
      const id = key.slice(prefix.length);
      if (!id || !(values[index] instanceof Uint8Array || values[index] instanceof ArrayBuffer)) {
        throw new Error("Encrypted outbox record is malformed.");
      }
      records.push({
        id,
        plaintext: profile.openLocalRecord(
          await recordBindingKey(`outbox:${key}`),
          bytes(values[index] as Uint8Array | ArrayBuffer),
        ),
      });
    }
    return records;
  }

  async deleteOutbox(namespace: "real" | "decoy", id: string): Promise<void> {
    const transaction = (await this.database).transaction(OUTBOX_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(OUTBOX_STORE).delete(`${namespace}:${id}`);
    await completion;
  }

  async openRecord(
    profile: WasmProfileHandle,
    id: string,
  ): Promise<Uint8Array | undefined> {
    const transaction = (await this.database).transaction(RECORD_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const encrypted = await requestResult(
      transaction.objectStore(RECORD_STORE).get(id) as IDBRequest<Uint8Array | ArrayBuffer | undefined>,
    );
    await completion;
    return encrypted === undefined
      ? undefined
      : profile.openLocalRecord(await recordBindingKey(id), bytes(encrypted));
  }

  async saveSessionSnapshot(id: string, encryptedSnapshot: Uint8Array): Promise<void> {
    const transaction = (await this.database).transaction(SESSION_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(SESSION_STORE).put(encryptedSnapshot, id);
    await completion;
  }

  async readSessionSnapshot(id: string): Promise<Uint8Array | undefined> {
    const transaction = (await this.database).transaction(SESSION_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const snapshot = await requestResult(
      transaction.objectStore(SESSION_STORE).get(id) as IDBRequest<Uint8Array | ArrayBuffer | undefined>,
    );
    await completion;
    return snapshot === undefined ? undefined : bytes(snapshot);
  }

  async exportBackup(password?: string): Promise<Uint8Array> {
    const container = await this.readBackupContainer();
    const plaintext = new TextEncoder().encode(JSON.stringify(container));
    const body = password
      ? (await loadCryptoWasm()).encrypt_backup(password, plaintext)
      : plaintext;
    if (BACKUP_MAGIC.length + 1 + body.length > MAX_BACKUP_SIZE) {
      throw new Error("Backup container exceeds the file size limit.");
    }
    const result = new Uint8Array(BACKUP_MAGIC.length + 1 + body.length);
    result.set(BACKUP_MAGIC);
    result[BACKUP_MAGIC.length] = password ? 1 : 0;
    result.set(body, BACKUP_MAGIC.length + 1);
    return result;
  }

  async importBackup(encoded: Uint8Array, password?: string): Promise<void> {
    if (
      encoded.length < BACKUP_MAGIC.length + 2 ||
      encoded.length > MAX_BACKUP_SIZE ||
      BACKUP_MAGIC.some((byte, index) => encoded[index] !== byte)
    ) {
      throw new Error("Backup container is malformed or too large.");
    }
    const mode = encoded[BACKUP_MAGIC.length];
    if (mode !== 0 && mode !== 1) throw new Error("Backup protection mode is unsupported.");
    let plaintext = encoded.slice(BACKUP_MAGIC.length + 1);
    if (mode === 1) {
      if (!password) throw new Error("This backup requires its backup password.");
      plaintext = (await loadCryptoWasm()).decrypt_backup(password, plaintext);
    }
    const container = parseBackupContainer(plaintext);
    const db = await this.database;
    const transaction = db.transaction([...BACKUP_STORES], "readwrite");
    const completion = transactionCompletion(transaction);
    let remainingChecks = BACKUP_STORES.length;
    let occupied = false;
    for (const storeName of BACKUP_STORES) {
      const request = transaction.objectStore(storeName).count();
      request.onsuccess = () => {
        occupied ||= request.result > 0;
        remainingChecks -= 1;
        if (remainingChecks !== 0) return;
        if (occupied) {
          transaction.abort();
          return;
        }
        for (const name of BACKUP_STORES) {
          for (const entry of container.stores[name]) {
            transaction.objectStore(name).put(decodeBackupValue(entry), entry.key);
          }
        }
      }
    }
    try {
      await completion;
    } catch (error) {
      if (occupied) {
        throw new Error("Backup import requires an empty local vault; existing data was not changed.");
      }
      throw error;
    }
  }

  async claimOneTimeInvitation(invitation: Uint8Array): Promise<void> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", invitation));
    const key = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const transaction = (await this.database).transaction(USED_INVITATION_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    const store = transaction.objectStore(USED_INVITATION_STORE);
    const existing = store.get(key);
    let alreadyUsed = false;
    existing.onsuccess = () => {
      if (existing.result !== undefined) {
        alreadyUsed = true;
        transaction.abort();
      } else {
        store.put(true, key);
      }
    };
    try {
      await completion;
    } catch (error) {
      if (alreadyUsed) throw new Error("This one-time invitation has already been used.");
      throw error;
    }
  }

  async deleteRealKeyWrap(): Promise<DeletionReceipt> {
    if ((await this.duressState()) !== "DURESS_PENDING_CLEANUP") {
      throw new Error("Real key wrapper deletion requires DURESS_PENDING_CLEANUP.");
    }
    const db = await this.database;
    const transaction = db.transaction(KEY_WRAP_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(KEY_WRAP_STORE).delete(REAL_WRAP_KEY);
    await completion;
    if ((await this.readWrap(REAL_WRAP_KEY)) !== undefined) {
      throw new Error("IndexedDB committed, but the real key wrapper remains present.");
    }
    return Object.freeze({ confirmed: true, [receiptBrand]: true as const });
  }

  async markDuressActive(receipt: DeletionReceipt): Promise<void> {
    if (receipt[receiptBrand] !== true || (await this.duressState()) !== "DURESS_PENDING_CLEANUP") {
      throw new Error("Decoy activation requires a valid key-wrapper deletion receipt.");
    }
    if ((await this.readWrap(REAL_WRAP_KEY)) !== undefined) {
      throw new Error("Real key wrapper remains present.");
    }
    await this.writeDuressState("ACTIVE");
  }

  async close(): Promise<void> {
    (await this.database).close();
  }

  private async readMetadata(key: string): Promise<unknown> {
    const transaction = (await this.database).transaction(METADATA_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const value = await requestResult(transaction.objectStore(METADATA_STORE).get(key));
    await completion;
    return value;
  }

  private async readWrap(key: string): Promise<Uint8Array | undefined> {
    const transaction = (await this.database).transaction(KEY_WRAP_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const value = await requestResult(
      transaction.objectStore(KEY_WRAP_STORE).get(key) as IDBRequest<Uint8Array | ArrayBuffer | undefined>,
    );
    await completion;
    return value === undefined ? undefined : bytes(value);
  }

  private async writeDuressState(state: DuressStorageState): Promise<void> {
    const transaction = (await this.database).transaction(METADATA_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(METADATA_STORE).put(state, DURESS_STATE_KEY);
    await completion;
  }

  private async readBackupContainer(): Promise<BackupContainer> {
    const db = await this.database;
    const transaction = db.transaction([...BACKUP_STORES], "readonly");
    const completion = transactionCompletion(transaction);
    const stores = {} as Record<string, BackupEntry[]>;
    await Promise.all(BACKUP_STORES.map(async (storeName) => {
      const store = transaction.objectStore(storeName);
      const [keys, values] = await Promise.all([
        requestResult(store.getAllKeys()),
        requestResult(store.getAll()),
      ]);
      stores[storeName] = keys.map((key, index) => {
        if (typeof key !== "string") throw new Error("Unexpected IndexedDB backup key type.");
        const value = values[index];
        if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
          return { key, kind: "bytes", value: encodeBytes(bytes(value)) };
        }
        if (typeof value === "string") return { key, kind: "string", value };
        if (typeof value === "boolean") return { key, kind: "boolean", value };
        throw new Error(`Unsupported IndexedDB value in ${storeName}.`);
      });
    }));
    await completion;
    return { version: 1, stores };
  }
}

function parseBackupContainer(encoded: Uint8Array): BackupContainer {
  if (encoded.length > MAX_BACKUP_SIZE - BACKUP_MAGIC.length - 1) {
    throw new Error("Backup contents exceed the size limit.");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
  } catch {
    throw new Error("Backup contents are not valid UTF-8 JSON.");
  }
  if (!value || typeof value !== "object") throw new Error("Backup contents are malformed.");
  const container = value as Partial<BackupContainer>;
  if (container.version !== 1 || !container.stores || typeof container.stores !== "object") {
    throw new Error("Backup version or store data is unsupported.");
  }
  const keys = Object.keys(container.stores);
  if (keys.length !== BACKUP_STORES.length || BACKUP_STORES.some((name) => !keys.includes(name))) {
    throw new Error("Backup does not contain the expected local stores.");
  }
  let entriesCount = 0;
  for (const storeName of BACKUP_STORES) {
    const entries = container.stores[storeName];
    if (!Array.isArray(entries)) throw new Error(`Backup store ${storeName} is malformed.`);
    entriesCount += entries.length;
    if (entriesCount > 10_000) throw new Error("Backup contains too many records.");
    const seen = new Set<string>();
    for (const candidate of entries) {
      if (
        !candidate ||
        typeof candidate !== "object" ||
        typeof candidate.key !== "string" ||
        !candidate.key ||
        seen.has(candidate.key) ||
        (candidate.kind !== "bytes" && candidate.kind !== "string" && candidate.kind !== "boolean") ||
        (candidate.kind === "boolean" && typeof candidate.value !== "boolean") ||
        (candidate.kind !== "boolean" && typeof candidate.value !== "string")
      ) {
        throw new Error(`Backup store ${storeName} contains an invalid entry.`);
      }
      if (candidate.kind === "bytes") {
        try {
          decodeBytes(candidate.value as string);
        } catch {
          throw new Error(`Backup store ${storeName} contains invalid binary data.`);
        }
      }
      seen.add(candidate.key);
    }
  }
  const metadata = new Map(container.stores[METADATA_STORE].map((entry) => [entry.key, entry]));
  const wraps = new Map(container.stores[KEY_WRAP_STORE].map((entry) => [entry.key, entry]));
  const duressState = metadata.get(DURESS_STATE_KEY)?.value;
  if (
    metadata.get(PROFILE_INITIALIZED_KEY)?.value !== true ||
    (duressState !== "NORMAL" && duressState !== "DURESS_PENDING_CLEANUP" && duressState !== "ACTIVE") ||
    !isValidKeyWrap(wraps.get(DECOY_WRAP_KEY)) ||
    (duressState === "NORMAL" && !isValidKeyWrap(wraps.get(REAL_WRAP_KEY))) ||
    (wraps.has(REAL_WRAP_KEY) && !isValidKeyWrap(wraps.get(REAL_WRAP_KEY))) ||
    (duressState === "ACTIVE" && wraps.has(REAL_WRAP_KEY))
  ) {
    throw new Error("Backup is missing consistent profile or key-wrapper state.");
  }
  return container as BackupContainer;
}

function decodeBackupValue(entry: BackupEntry): Uint8Array | string | boolean {
  if (entry.kind === "bytes") {
    if (typeof entry.value !== "string") throw new Error("Backup binary value is malformed.");
    return decodeBytes(entry.value);
  }
  return entry.value as string | boolean;
}

function isValidKeyWrap(entry: BackupEntry | undefined): boolean {
  if (entry?.kind !== "bytes" || typeof entry.value !== "string") return false;
  try {
    const wrapped = decodeBytes(entry.value);
    return (
      wrapped.length === 84 &&
      new TextDecoder().decode(wrapped.subarray(0, 8)) === "USTOYKW1"
    );
  } catch {
    return false;
  }
}
