export type PersistentDuressState =
  | "NORMAL"
  | "DURESS_PENDING_CLEANUP"
  | "ACTIVE";

const receiptBrand: unique symbol = Symbol("ustoy-deletion-receipt");

export type DeletionReceipt = Readonly<{
  outcome: "transaction-committed-and-absence-verified";
  [receiptBrand]: true;
}>;

export interface KeyWrapStorage {
  ensureDemoState(): Promise<void>;
  duressState(): Promise<PersistentDuressState>;
  markDuressPendingCleanup(): Promise<void>;
  deleteRealKeyWrap(): Promise<DeletionReceipt>;
  markDuressActive(receipt: DeletionReceipt): Promise<void>;
}

export interface DemoStorageInspection {
  state: PersistentDuressState;
  realKeyWrapPresent: boolean;
  decoyKeyWrapPresent: boolean;
}

const DATABASE_NAME = "ustoy-client-demo";
const DATABASE_VERSION = 1;
const METADATA_STORE = "metadata";
const KEY_WRAP_STORE = "key-wrap-markers";
const DEMO_INITIALIZED_KEY = "demo-initialized";
const DURESS_STATE_KEY = "duress-state";
const DEMO_ONLY_MARKER = Object.freeze({ demoOnly: true, containsNoKey: true });

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionCompletion(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}

function createDeletionReceipt(): DeletionReceipt {
  return Object.freeze({
    outcome: "transaction-committed-and-absence-verified",
    [receiptBrand]: true as const,
  });
}

export class IndexedDbKeyWrapStorage implements KeyWrapStorage {
  private readonly database: Promise<IDBDatabase>;
  private failNextDelete = false;

  constructor() {
    if (!("indexedDB" in globalThis)) {
      throw new Error("IndexedDB недоступен в этом браузере.");
    }
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(METADATA_STORE)) {
          db.createObjectStore(METADATA_STORE);
        }
        if (!db.objectStoreNames.contains(KEY_WRAP_STORE)) {
          db.createObjectStore(KEY_WRAP_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Не удалось открыть IndexedDB."));
      request.onblocked = () => reject(new Error("Открытие IndexedDB заблокировано."));
    });
  }

  async ensureDemoState(): Promise<void> {
    const db = await this.database;
    const transaction = db.transaction(
      [METADATA_STORE, KEY_WRAP_STORE],
      "readwrite",
    );
    const completion = transactionCompletion(transaction);
    const metadata = transaction.objectStore(METADATA_STORE);
    const initialized = metadata.get(DEMO_INITIALIZED_KEY);

    initialized.onsuccess = () => {
      if (initialized.result === true) return;
      metadata.put(true, DEMO_INITIALIZED_KEY);
      metadata.put("NORMAL", DURESS_STATE_KEY);
      const wraps = transaction.objectStore(KEY_WRAP_STORE);
      wraps.put(DEMO_ONLY_MARKER, "real");
      wraps.put(DEMO_ONLY_MARKER, "decoy");
    };

    await completion;
  }

  async duressState(): Promise<PersistentDuressState> {
    const db = await this.database;
    const transaction = db.transaction(METADATA_STORE, "readonly");
    const completion = transactionCompletion(transaction);
    const state = await requestResult(
      transaction.objectStore(METADATA_STORE).get(DURESS_STATE_KEY),
    );
    await completion;
    if (
      state === "NORMAL" ||
      state === "DURESS_PENDING_CLEANUP" ||
      state === "ACTIVE"
    ) {
      return state;
    }
    return "NORMAL";
  }

  async markDuressPendingCleanup(): Promise<void> {
    await this.writeDuressState("DURESS_PENDING_CLEANUP");
  }

  async deleteRealKeyWrap(): Promise<DeletionReceipt> {
    if (this.failNextDelete) {
      this.failNextDelete = false;
      throw new Error("Демо-сбой: хранилище не подтвердило удаление key wrap.");
    }
    if ((await this.duressState()) !== "DURESS_PENDING_CLEANUP") {
      throw new Error("Удаление real key wrap разрешено только в состоянии DURESS_PENDING_CLEANUP.");
    }

    const db = await this.database;
    const transaction = db.transaction(KEY_WRAP_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(KEY_WRAP_STORE).delete("real");
    await completion;

    const inspection = await this.inspectDemoState();
    if (inspection.realKeyWrapPresent) {
      throw new Error("IndexedDB завершил транзакцию, но key wrap всё ещё существует.");
    }
    return createDeletionReceipt();
  }

  async markDuressActive(receipt: DeletionReceipt): Promise<void> {
    if (receipt[receiptBrand] !== true) {
      throw new Error("Не получено подтверждение удаления key wrap.");
    }
    const inspection = await this.inspectDemoState();
    if (
      inspection.state !== "DURESS_PENDING_CLEANUP" ||
      inspection.realKeyWrapPresent
    ) {
      throw new Error("Нельзя активировать decoy до подтверждённого удаления key wrap.");
    }
    await this.writeDuressState("ACTIVE");
  }

  async inspectDemoState(): Promise<DemoStorageInspection> {
    const db = await this.database;
    const transaction = db.transaction(
      [METADATA_STORE, KEY_WRAP_STORE],
      "readonly",
    );
    const completion = transactionCompletion(transaction);
    const metadata = transaction.objectStore(METADATA_STORE);
    const wraps = transaction.objectStore(KEY_WRAP_STORE);
    const [state, real, decoy] = await Promise.all([
      requestResult(metadata.get(DURESS_STATE_KEY)),
      requestResult(wraps.get("real")),
      requestResult(wraps.get("decoy")),
    ]);
    await completion;

    const duressState =
      state === "DURESS_PENDING_CLEANUP" || state === "ACTIVE" ? state : "NORMAL";
    return {
      state: duressState,
      realKeyWrapPresent: real !== undefined,
      decoyKeyWrapPresent: decoy !== undefined,
    };
  }

  failNextDeleteForDemo(): void {
    this.failNextDelete = true;
  }

  async close(): Promise<void> {
    (await this.database).close();
  }

  private async writeDuressState(state: PersistentDuressState): Promise<void> {
    const db = await this.database;
    const transaction = db.transaction(METADATA_STORE, "readwrite");
    const completion = transactionCompletion(transaction);
    transaction.objectStore(METADATA_STORE).put(state, DURESS_STATE_KEY);
    await completion;
  }
}
