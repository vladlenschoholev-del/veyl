import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  WasmClientBridge,
  type LiveChat,
  type LiveMessage,
} from "../client-bridge";
import { RelayClient } from "../client-bridge/relayClient";
import { loadCryptoWasm } from "../client-bridge/wasm-runtime";
import { EncryptedIndexedDbStorage } from "../storage-adapter/encrypted-storage";
import type { WasmProfileHandle } from "../client-bridge/wasm-runtime";

type Phase = "loading" | "setup" | "locked" | "ready" | "cleanup-pending";
type RelayHealthState = "checking" | "available" | "unavailable" | "cors-network-error";

function relayOrigin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

function relayUrlsForDisplay(incoming: string, outgoing: string): string[] {
  return [...new Set([incoming, outgoing])];
}

function torDiagnostic(incoming: string, outgoing: string): string {
  const usesOnion = [incoming, outgoing].some((value) => {
    try {
      return new URL(value).hostname.endsWith(".onion");
    } catch {
      return false;
    }
  });
  return usesOnion
    ? "выбран onion relay; работу Tor браузера нельзя проверить из страницы"
    : "не используется браузерным fetch (нужен Tor Browser или native SOCKS5 transport)";
}

function deliveryLabel(delivery: LiveMessage["delivery"]): string {
  if (delivery === "pending") return "Ожидает отправки";
  if (delivery === "queued") return "принято релеем";
  return "Ratchet-зашифровано";
}

function relayHealthLabel(status: RelayHealthState): string {
  switch (status) {
    case "checking": return "проверяется";
    case "available": return "доступен";
    case "unavailable": return "недоступен";
    case "cors-network-error": return "ошибка CORS или сети (браузер не различает)";
  }
}

function wasmStatusLabel(status: "loading" | "available" | "unavailable"): string {
  if (status === "loading") return "загружается";
  if (status === "available") return "готов";
  return "не загружен";
}

function imageDataUrl(message: LiveMessage): string | undefined {
  if (message.content.kind !== "image") return undefined;
  const raw = message.content.bytes.replaceAll("-", "+").replaceAll("_", "/");
  const base64 = raw.padEnd(Math.ceil(raw.length / 4) * 4, "=");
  return `data:${message.content.mimeType};base64,${base64}`;
}

export function LiveCryptoPanel({ onBack }: { onBack: () => void }) {
  const [storage] = useState(() => new EncryptedIndexedDbStorage());
  const [phase, setPhase] = useState<Phase>("loading");
  const [initialized, setInitialized] = useState(false);
  const [pin, setPin] = useState("");
  const [primaryPin, setPrimaryPin] = useState("");
  const [duressPin, setDuressPin] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [backupImportPassword, setBackupImportPassword] = useState("");
  const [wasmStatus, setWasmStatus] = useState<"loading" | "available" | "unavailable">("loading");
  const [relayHealth, setRelayHealth] = useState<Record<string, RelayHealthState>>({});
  const [incomingRelay, setIncomingRelay] = useState("http://127.0.0.1:5173");
  const [outgoingRelay, setOutgoingRelay] = useState("http://127.0.0.1:5173");
  const [contactName, setContactName] = useState("");
  const [invitation, setInvitation] = useState("");
  const [reply, setReply] = useState("");
  const [importedInvitation, setImportedInvitation] = useState("");
  const [sasInput, setSasInput] = useState("");
  const [sasCompared, setSasCompared] = useState(false);
  const [draft, setDraft] = useState("");
  const [profileMode, setProfileMode] = useState("");
  const [chats, setChats] = useState<LiveChat[]>([]);
  const [selectedChatId, setSelectedChatId] = useState("");
  const [pendingChatId, setPendingChatId] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const runtime = useRef<{
    bridge: WasmClientBridge;
    profile: WasmProfileHandle;
  } | null>(null);

  useEffect(() => {
    let active = true;
    void storage
      .isProfileInitialized()
      .then(async (hasProfile) => {
        if (!active) return;
        setInitialized(hasProfile);
        if (!hasProfile) {
          setPhase("setup");
          return;
        }
        try {
          await storage.recoverPendingDuress();
          if (active) setPhase("locked");
        } catch (error) {
          if (active) {
            setPhase("cleanup-pending");
            setNotice(error instanceof Error ? error.message : "Duress cleanup remains pending.");
          }
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setPhase("cleanup-pending");
          setNotice(error instanceof Error ? error.message : "Unable to inspect local storage.");
        }
      });
    return () => {
      active = false;
      runtime.current?.bridge.lock();
      runtime.current?.profile.free();
      runtime.current = null;
      void storage.close();
    };
  }, [storage]);

  useEffect(() => {
    if (phase !== "ready") return;
    let active = true;
    const relayUrls = [...new Set([incomingRelay, outgoingRelay])];
    const checkRelays = async () => {
      await Promise.all(relayUrls.map(async (url) => {
        let status: RelayHealthState;
        try {
          await new RelayClient(url).health();
          status = "available";
        } catch (error) {
          status = error instanceof Error && error.message.includes("HTTP ")
            ? "unavailable"
            : "cors-network-error";
        }
        if (active) setRelayHealth((current) => ({ ...current, [relayOrigin(url)]: status }));
      }));
    };
    const retryOutbox = async () => {
      try {
        const result = await runtime.current?.bridge.retryOutbox();
        if (!active || !result) return;
        if (result.sent > 0) {
          setChats(runtime.current?.bridge.listChats() ?? []);
          setNotice(`${result.sent} pending encrypted message(s) accepted by the relay.`);
        }
        if (result.failed > 0 && result.error) setNotice(`Outbox retry pending: ${result.error}`);
      } catch (error) {
        if (active) setNotice(error instanceof Error ? error.message : "Outbox retry failed.");
      }
    };
    const refresh = () => {
      void checkRelays();
      void retryOutbox();
    };
    void loadCryptoWasm()
      .then(() => active && setWasmStatus("available"))
      .catch(() => active && setWasmStatus("unavailable"));
    refresh();
    const interval = window.setInterval(refresh, 15_000);
    window.addEventListener("online", refresh);
    return () => {
      active = false;
      window.clearInterval(interval);
      window.removeEventListener("online", refresh);
    };
  }, [incomingRelay, outgoingRelay, phase]);

  const selectedChat = chats.find((chat) => chat.id === selectedChatId) ?? null;

  useEffect(() => {
    setSasInput("");
    setSasCompared(false);
  }, [selectedChatId]);

  const unlockOrInitialize = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      let unlockPin = pin;
      if (!initialized) {
        unlockPin = primaryPin;
        await storage.initializeProfile(primaryPin, duressPin);
        setInitialized(true);
        setPhase("locked");
        setPrimaryPin("");
        setDuressPin("");
      }
      const unlocked = await storage.unlock(unlockPin);
      const bridge = new WasmClientBridge(storage, unlocked.profile, {
        incoming: incomingRelay,
        outgoing: outgoingRelay,
      }, unlocked.mode === "DECOY" ? "decoy" : "real");
      let restored: LiveChat[];
      try {
        restored = await bridge.restoreChats();
      } catch (error) {
        bridge.lock();
        unlocked.profile.free();
        throw error;
      }
      runtime.current = { bridge, profile: unlocked.profile };
      setChats(restored);
      setSelectedChatId(restored[0]?.id ?? "");
      setProfileMode(unlocked.mode);
      setPhase("ready");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Vault unlock failed.");
    } finally {
      setPin("");
      setPrimaryPin("");
      setDuressPin("");
      setBusy(false);
    }
  };

  const createInvitation = async () => {
    const bridge = runtime.current?.bridge;
    if (!bridge) return;
    setBusy(true);
    try {
      const created = await bridge.createInvitation(contactName);
      setPendingChatId(created.chatId);
      setInvitation(created.link);
      setReply("");
      setNotice("Share this one-time invitation out of band. It contains a queue write capability.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Invitation creation failed.");
    } finally {
      setBusy(false);
    }
  };

  const acceptInvitation = async () => {
    const bridge = runtime.current?.bridge;
    if (!bridge) return;
    setBusy(true);
    try {
      const accepted = await bridge.acceptInvitation(importedInvitation, contactName);
      setInvitation(accepted.replyLink);
      setPendingChatId(accepted.chatId);
      setSasInput("");
      setChats(bridge.listChats());
      setSelectedChatId(accepted.chatId);
      setNotice("Return the reply link out of band, then compare the SAS in person.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Invitation was rejected.");
    } finally {
      setBusy(false);
    }
  };

  const completeHandshake = async () => {
    const bridge = runtime.current?.bridge;
    if (!bridge || !pendingChatId) return;
    setBusy(true);
    try {
      await bridge.completeInvitation(pendingChatId, reply);
      setChats(bridge.listChats());
      setSelectedChatId(pendingChatId);
      setSasInput("");
      setReply("");
      setNotice("Handshake complete, but this session remains UNVERIFIED until you compare the SAS.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Handshake reply was rejected.");
    } finally {
      setBusy(false);
    }
  };

  const confirmSas = async () => {
    const bridge = runtime.current?.bridge;
    if (!bridge || !selectedChat) return;
    if (!sasCompared) {
      setNotice("Confirm that you compared this code with the peer in person.");
      return;
    }
    setBusy(true);
    try {
      await bridge.confirmSas(selectedChat.id, sasInput);
      setChats(bridge.listChats());
      setNotice("SAS verified cryptographically for this session.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "SAS verification failed.");
    } finally {
      setBusy(false);
    }
  };

  const sendText = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const bridge = runtime.current?.bridge;
    if (!bridge || !selectedChat || !draft.trim()) return;
    setBusy(true);
    try {
      await bridge.sendText(selectedChat.id, draft);
      setDraft("");
      setChats(bridge.listChats());
      setNotice("Message encrypted and stored locally; it will retry automatically if the relay is unavailable.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Message send failed.");
    } finally {
      setBusy(false);
    }
  };

  const sendImage = async (file?: File) => {
    const bridge = runtime.current?.bridge;
    if (!bridge || !selectedChat || !file) return;
    setBusy(true);
    try {
      await bridge.sendImage(selectedChat.id, file);
      setChats(bridge.listChats());
      setNotice("JPEG/PNG was re-encoded in Rust/Wasm before encryption.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Image processing failed.");
    } finally {
      setBusy(false);
    }
  };

  const exportBackup = async () => {
    if (!window.confirm(
      "A .ustoy file contains encrypted profile data and PIN-protected key wraps. Duress cannot remove exported copies. Continue?",
    )) return;
    if (backupPassword && backupPassword.length < 8) {
      setNotice("An additional backup password must contain at least 8 characters.");
      return;
    }
    setBusy(true);
    try {
      const bytes = await storage.exportBackup(backupPassword || undefined);
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `ustoy-${new Date().toISOString().slice(0, 10)}.ustoy`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      setBackupPassword("");
      setNotice("Encrypted profile backup exported. Store it separately; duress cannot erase it.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Backup export failed.");
    } finally {
      setBusy(false);
    }
  };

  const importBackup = async (file?: File) => {
    if (!file) return;
    if (file.size > 128 * 1024 * 1024) {
      setNotice("Backup file exceeds the 128 MiB limit.");
      return;
    }
    setBusy(true);
    try {
      await storage.importBackup(new Uint8Array(await file.arrayBuffer()), backupImportPassword || undefined);
      setInitialized(true);
      setPhase("locked");
      setBackupImportPassword("");
      setNotice("Backup imported. Unlock it with the original profile PIN.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Backup import failed.");
    } finally {
      setBusy(false);
    }
  };

  const poll = async () => {
    const bridge = runtime.current?.bridge;
    if (!bridge || !selectedChat) return;
    setBusy(true);
    try {
      await bridge.poll(selectedChat.id);
      setChats(bridge.listChats());
      setNotice("Incoming queue checked; successfully processed records were acknowledged to the relay.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Relay polling failed.");
    } finally {
      setBusy(false);
    }
  };

  const lockVault = () => {
    runtime.current?.bridge.lock();
    runtime.current?.profile.free();
    runtime.current = null;
    setChats([]);
    setSelectedChatId("");
    setProfileMode("");
    setPhase("locked");
  };

  return (
    <section className="live-client-panel">
      <header className="live-client-header">
        <button className="button button-secondary" onClick={onBack}>Back to UI demo</button>
        <div>
          <p className="eyebrow">RUST / WASM · LIVE CLIENT</p>
          <h1>Local encrypted messenger</h1>
        </div>
        {profileMode && <span className="pill">LOCAL</span>}
        {phase === "ready" && (
          <button className="button button-secondary" onClick={lockVault}>
            Lock vault
          </button>
        )}
      </header>

      {phase !== "ready" ? (
        <form className="panel live-vault-form" onSubmit={unlockOrInitialize}>
          <h2>{phase === "setup" ? "Create local vault" : "Unlock local vault"}</h2>
          <p>PINs are used only by the Rust Argon2id key-wrap implementation and are not stored.</p>
          {phase === "cleanup-pending" && (
            <p role="alert">DURESS_PENDING_CLEANUP: real profile remains locked until key-wrap deletion is confirmed.</p>
          )}
          {phase === "loading" ? (
            <p>Checking IndexedDB…</p>
          ) : phase !== "cleanup-pending" ? (
            <>
              {phase === "setup" && (
                <>
                  <label>Primary PIN<input minLength={8} required type="password" value={primaryPin} onChange={(event) => setPrimaryPin(event.target.value)} /></label>
                  <label>Duress PIN<input minLength={8} required type="password" value={duressPin} onChange={(event) => setDuressPin(event.target.value)} /></label>
                  <label>Backup password (if the selected .ustoy file uses one)<input minLength={8} type="password" value={backupImportPassword} onChange={(event) => setBackupImportPassword(event.target.value)} /></label>
                  <label className="button button-secondary">
                    Import encrypted .ustoy
                    <input accept=".ustoy,application/octet-stream" hidden type="file" onChange={(event) => {
                      void importBackup(event.target.files?.[0]);
                      event.currentTarget.value = "";
                    }} />
                  </label>
                </>
              )}
              {phase === "locked" && (
                <label>PIN<input required type="password" value={pin} onChange={(event) => setPin(event.target.value)} /></label>
              )}
              <label>Incoming relay<input value={incomingRelay} onChange={(event) => setIncomingRelay(event.target.value)} /></label>
              <label>Outgoing relay<input value={outgoingRelay} onChange={(event) => setOutgoingRelay(event.target.value)} /></label>
              <button className="button button-primary" disabled={busy} type="submit">
                {phase === "setup" ? "Create and unlock" : "Unlock"}
              </button>
            </>
          ) : (
            <button
              className="button button-primary"
              disabled={busy}
              type="button"
              onClick={() => {
                setBusy(true);
                void storage.recoverPendingDuress()
                  .then(() => {
                    setPhase("locked");
                    setNotice("Cleanup completed; only the decoy profile can now be unlocked.");
                  })
                  .catch((error: unknown) => setNotice(error instanceof Error ? error.message : "Cleanup failed."))
                  .finally(() => setBusy(false));
              }}
            >
              Retry key-wrap cleanup
            </button>
          )}
          {notice && <p role="status">{notice}</p>}
        </form>
      ) : (
        <>
        <div className="live-diagnostics" aria-live="polite">
          <p>Модуль Wasm: <strong>{wasmStatusLabel(wasmStatus)}</strong></p>
          {relayUrlsForDisplay(incomingRelay, outgoingRelay).map((url) => (
            <p key={url}>Релей {url}: <strong>{relayHealthLabel(relayHealth[relayOrigin(url)] ?? "checking")}</strong></p>
          ))}
          <p>Tor/SOCKS5: <strong>{torDiagnostic(incomingRelay, outgoingRelay)}</strong></p>
        </div>
        <div className="live-client-grid">
          <aside className="panel live-chat-list">
            <h2>Independent chats</h2>
            {chats.map((chat) => (
              <button
                className="button button-secondary"
                key={chat.id}
                onClick={() => setSelectedChatId(chat.id)}
              >
                {chat.name} · {chat.verified ? "VERIFIED" : "UNVERIFIED"}
              </button>
            ))}
            <label>Contact name<input value={contactName} onChange={(event) => setContactName(event.target.value)} /></label>
            <button className="button button-primary" disabled={busy} onClick={() => void createInvitation()}>
              Create one-time invite
            </button>
            <label>Invite link<input value={importedInvitation} onChange={(event) => setImportedInvitation(event.target.value)} /></label>
            <button className="button button-secondary" disabled={busy || !importedInvitation} onClick={() => void acceptInvitation()}>
              Accept invite
            </button>
            <label>Handshake reply<input value={reply} onChange={(event) => setReply(event.target.value)} /></label>
            <button className="button button-secondary" disabled={busy || !reply} onClick={() => void completeHandshake()}>
              Complete handshake
            </button>
            {invitation && (
              <>
                <QRCodeSVG value={invitation} size={180} level="M" />
                <textarea aria-label="Shareable invitation or reply" readOnly value={invitation} />
              </>
            )}
          </aside>

          <section className="panel live-chat-detail">
            {selectedChat ? (
              <>
                <header>
                  <h2>{selectedChat.name}</h2>
                  <p>{selectedChat.verified ? "VERIFIED" : "UNVERIFIED · active MITM remains possible until SAS comparison"}</p>
                </header>
                <div className="live-sas">
                  <strong>Compare this 48-bit SAS with the peer: {selectedChat.sas.match(/.{1,3}/g)?.join(" ")}</strong>
                  <label>Enter the independently compared code<input maxLength={12} value={sasInput} onChange={(event) => setSasInput(event.target.value.toUpperCase())} /></label>
                  <label className="sas-confirm-check">
                    <input type="checkbox" checked={sasCompared} onChange={(event) => setSasCompared(event.target.checked)} />
                    I compared the code with the peer in person
                  </label>
                  <button className="button button-secondary" disabled={busy || selectedChat.verified || !sasCompared || sasInput.length !== 12} onClick={() => void confirmSas()}>
                    Confirm verified session
                  </button>
                </div>
                <div className="live-messages">
                  {selectedChat.messages.map((message) => (
                    <article className="live-message" key={message.id}>
                      {message.content.kind === "text"
                        ? <p>{message.content.text}</p>
                        : <img alt={message.content.name} src={imageDataUrl(message)} />}
                      <small>{message.direction} · {deliveryLabel(message.delivery)}</small>
                    </article>
                  ))}
                </div>
                <div className="live-chat-actions">
                  <form onSubmit={(event) => void sendText(event)}>
                    <input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Encrypted message" />
                    <button className="button button-primary" disabled={busy || !selectedChat.verified}>Send</button>
                  </form>
                  <label className="button button-secondary">
                    Attach JPEG/PNG
                    <input
                      accept="image/jpeg,image/png"
                      hidden
                      type="file"
                      onChange={(event) => {
                        void sendImage(event.target.files?.[0]);
                        event.currentTarget.value = "";
                      }}
                    />
                  </label>
                  <button className="button button-secondary" disabled={busy} onClick={() => void poll()}>
                    Poll incoming queue
                  </button>
                  <label>Optional backup password<input minLength={8} type="password" value={backupPassword} onChange={(event) => setBackupPassword(event.target.value)} /></label>
                  <button className="button button-secondary" disabled={busy} onClick={() => void exportBackup()}>
                    Export encrypted .ustoy
                  </button>
                  <p className="backup-warning">External backups survive Duress PIN cleanup. Without an extra backup password, the profile PIN still protects the included key wraps.</p>
                </div>
              </>
            ) : (
              profileMode === "DECOY" ? (
                <article className="live-message">
                  <strong>Заметки</strong>
                  <p>Купить чай и проверить список дел.</p>
                </article>
              ) : (
                <p>Create an invite or accept a peer's one-time invite to start a chat.</p>
              )
            )}
          </section>
          {notice && <p className="live-notice" role="status">{notice}</p>}
        </div>
        </>
      )}
    </section>
  );
}
