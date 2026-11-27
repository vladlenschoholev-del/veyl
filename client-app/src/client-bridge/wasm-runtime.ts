export interface WasmSessionHandle {
  sas(): string | undefined;
  verificationStatus(): string;
  confirmSas(entered: string): void;
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(relayPayload: Uint8Array): Uint8Array;
  free(): void;
}

export interface WasmProfileHandle {
  realKeyWrap(): Uint8Array;
  decoyKeyWrap(): Uint8Array;
  unlockWithPin(pin: string): string;
  activateDecoyAfterCleanup(): void;
  serializeSession(session: WasmSessionHandle): Uint8Array;
  restoreSession(snapshot: Uint8Array): WasmSessionHandle;
  sealLocalRecord(recordKey: Uint8Array, plaintext: Uint8Array): Uint8Array;
  openLocalRecord(recordKey: Uint8Array, encryptedRecord: Uint8Array): Uint8Array;
  free(): void;
}

export interface CryptoWasmApi {
  default(): Promise<unknown>;
  WasmProfile: {
    new (primaryPin: string, duressPin: string): WasmProfileHandle;
    fromStoredWraps(
      realWrap: Uint8Array,
      decoyWrap: Uint8Array,
      persistentState: string,
    ): WasmProfileHandle;
  };
  WasmInitiator: {
    new (): {
      publicBytes(): Uint8Array;
      finish(response: Uint8Array): WasmSessionHandle;
      free(): void;
    };
  };
  create_responder(offer: Uint8Array): {
    responseBytes(): Uint8Array;
    takeSession(): WasmSessionHandle;
    free(): void;
  };
  sanitize_image(input: Uint8Array): Uint8Array;
  pad_payload(input: Uint8Array): Uint8Array;
  unpad_payload(input: Uint8Array): Uint8Array;
  encrypt_backup(password: string, plaintext: Uint8Array): Uint8Array;
  decrypt_backup(password: string, encoded: Uint8Array): Uint8Array;
}

let modulePromise: Promise<CryptoWasmApi> | undefined;

export function loadCryptoWasm(): Promise<CryptoWasmApi> {
  modulePromise ??= (async () => {
    const url = new URL("crypto-wasm/crypto_wasm.js", document.baseURI).href;
    const wasm = (await import(/* @vite-ignore */ url)) as CryptoWasmApi;
    await wasm.default();
    return wasm;
  })();
  return modulePromise;
}
