import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EncryptedIndexedDbStorage } from "./encrypted-storage";
import type { WasmProfileHandle } from "../client-bridge/wasm-runtime";

function resetDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase("ustoy-client");
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("Could not reset IndexedDB."));
    request.onblocked = () => reject(new Error("IndexedDB reset was blocked."));
  });
}

describe("EncryptedIndexedDbStorage", () => {
  let storage: EncryptedIndexedDbStorage;

  beforeEach(async () => {
    await resetDatabase();
    storage = new EncryptedIndexedDbStorage();
  });

  afterEach(async () => {
    await storage.close();
  });

  it("persists opaque encrypted session snapshots", async () => {
    const snapshot = new Uint8Array([9, 8, 7, 6]);
    await storage.saveSessionSnapshot("random-chat-key", snapshot);
    await expect(storage.readSessionSnapshot("random-chat-key")).resolves.toEqual(snapshot);
    await expect(storage.readSessionSnapshot("missing")).resolves.toBeUndefined();
  });

  it("claims a one-time invitation once and rejects replay", async () => {
    const invitation = new Uint8Array([1, 2, 3, 4]);
    await storage.claimOneTimeInvitation(invitation);
    await expect(storage.claimOneTimeInvitation(invitation)).rejects.toThrow(
      "already been used",
    );
    await expect(storage.claimOneTimeInvitation(new Uint8Array([1, 2, 3, 5]))).resolves.toBeUndefined();
  });

  it("exports and imports a versioned .ustoy container only into an empty vault", async () => {
    const names = [
      "metadata",
      "key-wraps",
      "encrypted-records",
      "encrypted-sessions",
      "used-invitations",
      "encrypted-outbox",
    ];
    const wrapper = new Uint8Array(84);
    wrapper.set(new TextEncoder().encode("USTOYKW1"));
    const encodedWrapper = btoa(String.fromCharCode(...wrapper));
    const payload = new TextEncoder().encode(JSON.stringify({
      version: 1,
      stores: Object.fromEntries(names.map((name) => [
        name,
        name === "metadata"
          ? [
              { key: "profile-initialized", kind: "boolean", value: true },
              { key: "duress-state", kind: "string", value: "NORMAL" },
            ]
          : name === "key-wraps"
            ? [
                { key: "real", kind: "bytes", value: encodedWrapper },
                { key: "decoy", kind: "bytes", value: encodedWrapper },
              ]
            : [],
      ])),
    }));
    const magic = new TextEncoder().encode("USTOYF1\0");
    const backup = new Uint8Array(magic.length + 1 + payload.length);
    backup.set(magic);
    backup[magic.length] = 0;
    backup.set(payload, magic.length + 1);

    await storage.importBackup(backup);
    const exported = await storage.exportBackup();
    expect(new TextDecoder().decode(exported.slice(0, magic.length))).toBe("USTOYF1\0");
    await expect(storage.importBackup(exported)).rejects.toThrow("empty local vault");
  });

  it("persists outbox ciphertext alongside the ratchet snapshot and removes it after delivery", async () => {
    const profile: WasmProfileHandle = {
      realKeyWrap: () => new Uint8Array(),
      decoyKeyWrap: () => new Uint8Array(),
      unlockWithPin: () => "REAL",
      activateDecoyAfterCleanup: () => undefined,
      serializeSession: () => new Uint8Array(),
      restoreSession: () => {
        throw new Error("Not used by this storage test.");
      },
      sealLocalRecord: (_key, plaintext) => plaintext.slice(),
      openLocalRecord: (_key, ciphertext) => ciphertext.slice(),
      free: () => undefined,
    };
    const outbox = new TextEncoder().encode('{"packet":"ciphertext"}');
    const snapshot = new Uint8Array([5, 6, 7]);
    await storage.saveEncryptedChatState(
      profile,
      "real:chat-key",
      new Uint8Array([1, 2]),
      snapshot,
      { id: "retry-id", namespace: "real", plaintext: outbox },
    );

    await expect(storage.readSessionSnapshot("real:chat-key")).resolves.toEqual(snapshot);
    await expect(storage.listOutbox(profile, "real")).resolves.toEqual([
      { id: "retry-id", plaintext: outbox },
    ]);
    await storage.deleteOutbox("real", "retry-id");
    await expect(storage.listOutbox(profile, "real")).resolves.toEqual([]);
  });
});
