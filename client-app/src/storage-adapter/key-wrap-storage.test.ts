import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DemoClientBridge } from "../client-bridge";
import { IndexedDbKeyWrapStorage } from "./key-wrap-storage";

function deleteDemoDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase("ustoy-client-demo");
    request.onsuccess = () => resolve();
    request.onerror = () =>
      reject(request.error ?? new Error("Could not reset the test database."));
    request.onblocked = () => reject(new Error("Test database deletion was blocked."));
  });
}

describe("IndexedDbKeyWrapStorage duress contract", () => {
  let storage: IndexedDbKeyWrapStorage;

  beforeEach(async () => {
    await deleteDemoDatabase();
    storage = new IndexedDbKeyWrapStorage();
    await storage.ensureDemoState();
  });

  afterEach(async () => {
    await storage.close();
  });

  it("only activates the decoy after committed deletion is verified", async () => {
    await storage.markDuressPendingCleanup();
    const receipt = await storage.deleteRealKeyWrap();
    await storage.markDuressActive(receipt);

    await expect(storage.inspectDemoState()).resolves.toEqual({
      state: "ACTIVE",
      realKeyWrapPresent: false,
      decoyKeyWrapPresent: true,
    });
  });

  it("keeps cleanup pending after a failed deletion and permits retry", async () => {
    await storage.markDuressPendingCleanup();
    storage.failNextDeleteForDemo();

    await expect(storage.deleteRealKeyWrap()).rejects.toThrow(
      "хранилище не подтвердило удаление",
    );
    await expect(storage.inspectDemoState()).resolves.toEqual({
      state: "DURESS_PENDING_CLEANUP",
      realKeyWrapPresent: true,
      decoyKeyWrapPresent: true,
    });

    const receipt = await storage.deleteRealKeyWrap();
    await storage.markDuressActive(receipt);
    await expect(storage.duressState()).resolves.toBe("ACTIVE");
  });

  it("does not expose chats or activate a decoy while deletion is pending", async () => {
    const bridge = new DemoClientBridge(storage);
    await bridge.start();

    await expect(bridge.activateDuress(true)).rejects.toThrow(
      "хранилище не подтвердило удаление",
    );
    expect(bridge.getSnapshot().profileMode).toBe("pending");
    expect(bridge.getSnapshot().chats).toEqual([]);
    await expect(storage.duressState()).resolves.toBe("DURESS_PENDING_CLEANUP");

    await storage.close();
    storage = new IndexedDbKeyWrapStorage();
    const restartedBridge = new DemoClientBridge(storage);
    await restartedBridge.start();
    expect(restartedBridge.getSnapshot().profileMode).toBe("decoy");
    expect(restartedBridge.getSnapshot().chats.map((chat) => chat.name)).toEqual(["Заметки"]);
    await expect(storage.duressState()).resolves.toBe("ACTIVE");
  });
});
