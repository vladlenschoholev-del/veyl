import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { RefObject } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  DemoClientBridge,
  type Chat,
  type ChatMessage,
} from "./client-bridge";
import { LiveCryptoPanel } from "./components/LiveCryptoPanel";
import { UnsupportedAttachmentError } from "./client-bridge/media";
import { Button, Icon, Panel, Pill } from "./components/ui";
import { IndexedDbKeyWrapStorage } from "./storage-adapter/key-wrap-storage";

type Screen = "chats" | "security" | "duress";
type InviteTab = "invite" | "sas";

const SAS_WORDS = [
  "абрикос", "аврора", "агат", "айва", "аккорд", "алмаз", "альфа", "амбра",
  "анис", "апрель", "арка", "арфа", "астра", "атлас", "афина", "аэростат",
  "багет", "бархат", "баян", "белка", "берег", "бирюза", "блик", "брусника",
  "ваза", "валун", "вельвет", "ветер", "вишня", "волна", "ворон", "вьюга",
  "газель", "гамма", "гвоздика", "глина", "голубь", "гранит", "груша", "гудок",
  "дельта", "дождь", "долина", "доска", "дуб", "дымка", "ежевика", "ель",
  "жасмин", "жемчуг", "жираф", "журнал", "забота", "заря", "звезда", "зонт",
  "иволга", "игла", "изумруд", "ирис", "искра", "исток", "йод", "йота",
];

const SAS_ICONS = ["◆", "●", "▲", "☾", "✦", "⬟", "⌁", "✿", "◉", "⬢", "✧", "☼", "◈", "♧", "✺", "⊙"];

function sasWordPairs(sasHex: string): string[] {
  return (sasHex.match(/.{1,3}/g) ?? []).map((group) => {
    const value = Number.parseInt(group, 16);
    return `${SAS_WORDS[(value >> 6) & 63]} · ${SAS_WORDS[value & 63]}`;
  });
}

function formatSas(sasHex: string): string {
  return (sasHex.match(/.{1,3}/g) ?? []).join(" ");
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function lastMessage(chat: Chat): string {
  const message = chat.messages.at(-1);
  if (!message) return "Новый контакт";
  return message.attachment ? "Изображение" : message.body;
}

function deliveryLabel(message: ChatMessage): string {
  switch (message.delivery) {
    case "encrypted":
      return "Зашифровано Ratchet · демо";
    case "queued":
      return "Отправлено в очередь · демо";
    case "acknowledged":
      return "Ack получен · демо";
  }
}

export default function App() {
  const [bridge] = useState(
    () => new DemoClientBridge(new IndexedDbKeyWrapStorage()),
  );
  const state = useSyncExternalStore(bridge.subscribe, bridge.getSnapshot);
  const [screen, setScreen] = useState<Screen>("chats");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteTab, setInviteTab] = useState<InviteTab>("invite");
  const [inviteText, setInviteText] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [sasChecked, setSasChecked] = useState(false);
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState("");
  const [duressFailure, setDuressFailure] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const attachmentInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void bridge.start();
  }, [bridge]);

  const activeChat =
    state.chats.find((chat) => chat.id === state.activeChatId) ?? null;

  useEffect(() => {
    setSasChecked(false);
  }, [state.activeChatId]);

  const openNewChat = () => {
    bridge.createChat("Новый контакт");
    setInviteTab("invite");
    setInviteText("");
    setInviteOpen(true);
    setScreen("chats");
  };

  const generateInvitation = () => {
    if (!activeChat) {
      setNotice("Сначала создайте чат.");
      return;
    }
    try {
      bridge.createInvitation(activeChat.id);
      setNotice("");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Не удалось создать приглашение.");
    }
  };

  const importInvitation = () => {
    try {
      const chat = bridge.importInvitation(inviteText, inviteName);
      setInviteText("");
      setInviteTab("sas");
      setSasChecked(false);
      setNotice("");
      bridge.setActiveChat(chat.id);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Не удалось принять приглашение.");
    }
  };

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice("Скопировано в буфер обмена.");
    } catch {
      setNotice("Буфер обмена недоступен. Выделите текст и скопируйте вручную.");
    }
  };

  const sendMessage = async () => {
    if (!activeChat || !draft.trim()) return;
    try {
      await bridge.sendText(activeChat.id, draft);
      setDraft("");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Не удалось отправить сообщение.");
    }
  };

  const chooseAttachment = async (file?: File) => {
    if (!file || !activeChat) return;
    try {
      await bridge.sendImage(activeChat.id, file);
      setNotice("Изображение повторно закодировано для демонстрационного предпросмотра.");
    } catch (error) {
      setNotice(
        error instanceof UnsupportedAttachmentError
          ? error.message
          : error instanceof Error
            ? error.message
            : "Не удалось обработать вложение.",
      );
    } finally {
      if (attachmentInput.current) attachmentInput.current.value = "";
    }
  };

  const activateDuress = async () => {
    setNotice("");
    try {
      await bridge.activateDuress(duressFailure);
      setNotice("Демо-профиль активирован после подтверждения транзакции IndexedDB.");
    } catch (error) {
      await bridge.refreshStorageInspection().catch(() => undefined);
      setNotice(
        error instanceof Error
          ? error.message
          : "Очистка не подтверждена; профиль остаётся в ожидании.",
      );
    }
  };

  const retryDuress = async () => {
    setNotice("");
    try {
      await bridge.retryDuressCleanup();
      setNotice("Очистка подтверждена; открыт нейтральный демо-профиль.");
    } catch (error) {
      setNotice(
        error instanceof Error
          ? error.message
          : "Очистка не подтверждена; профиль остаётся в ожидании.",
      );
    }
  };

  const invitation = state.invitation;

  if (liveMode) {
    return <LiveCryptoPanel onBack={() => setLiveMode(false)} />;
  }

  return (
    <div className="app-shell min-h-screen bg-paper text-ink">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">у</div>
          <div>
            <div className="brand-name">устой</div>
            <div className="brand-caption">частная связь</div>
          </div>
        </div>

        <div className="demo-banner">
          <span className="demo-dot" />
          ИНТЕРАКТИВНОЕ ДЕМО
        </div>

        <nav className="primary-nav" aria-label="Основная навигация">
          <button
            className={`nav-item ${screen === "chats" ? "nav-item-active" : ""}`}
            onClick={() => setScreen("chats")}
          >
            <Icon>◷</Icon>
            <span>Сообщения</span>
            {screen === "chats" && <span className="nav-indicator" />}
          </button>
          <button
            className={`nav-item ${screen === "security" ? "nav-item-active" : ""}`}
            onClick={() => setScreen("security")}
          >
            <Icon>⌑</Icon>
            <span>Безопасность</span>
            {screen === "security" && <span className="nav-indicator" />}
          </button>
          <button
            className={`nav-item ${screen === "duress" ? "nav-item-active" : ""}`}
            onClick={() => setScreen("duress")}
          >
            <Icon>◉</Icon>
            <span>Тревожный профиль</span>
            {screen === "duress" && <span className="nav-indicator" />}
          </button>
          <button className="nav-item" onClick={() => setLiveMode(true)}>
            <Icon>⌁</Icon>
            <span>Rust/Wasm live client</span>
          </button>
        </nav>

        {screen === "chats" && (
          <div className="conversation-list">
            <div className="list-heading">
              <span>ДИАЛОГИ</span>
              <button
                className="icon-button"
                aria-label="Создать чат"
                title="Создать чат"
                onClick={openNewChat}
              >
                +
              </button>
            </div>
            {state.chats.map((chat) => (
              <button
                className={`conversation-item ${chat.id === state.activeChatId ? "conversation-item-active" : ""}`}
                key={chat.id}
                onClick={() => bridge.setActiveChat(chat.id)}
              >
                <div className="avatar">{chat.name.slice(0, 1).toUpperCase()}</div>
                <div className="conversation-copy">
                  <div className="conversation-name-row">
                    <span className="conversation-name">{chat.name}</span>
                    <span className="conversation-time">
                      {chat.messages.at(-1) ? formatTime(chat.messages.at(-1)!.sentAt) : ""}
                    </span>
                  </div>
                  <div className="conversation-preview">{lastMessage(chat)}</div>
                </div>
                {!chat.verified && <span className="unverified-dot" title="UNVERIFIED" />}
              </button>
            ))}
            {state.chats.length === 0 && (
              <div className="empty-sidebar">
                Данные скрыты до подтверждения duress-контракта.
              </div>
            )}
          </div>
        )}

        <div className="sidebar-footer">
          <div className="profile-avatar">
            {state.profileMode === "decoy" ? "З" : "Я"}
          </div>
          <div className="profile-copy">
            <strong>
              {state.profileMode === "decoy"
                ? "Нейтральный профиль"
                : state.profileMode === "pending"
                  ? "Ожидание очистки"
                  : "Локальный профиль"}
            </strong>
            <span>без аккаунта и номера</span>
          </div>
          <span className="online-indicator" />
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-title">
            {screen === "chats" ? (
              <>
                <span className="topbar-eyebrow">ПРОСТРАНСТВО</span>
                <span className="topbar-heading">
                  {state.profileMode === "decoy" ? "Нейтральный профиль" : "Личные сообщения"}
                </span>
              </>
            ) : (
              <>
                <span className="topbar-eyebrow">УСТОЙ · НАСТРОЙКИ</span>
                <span className="topbar-heading">
                  {screen === "security" ? "Безопасность и самопроверка" : "Тревожный профиль"}
                </span>
              </>
            )}
          </div>
          <div className="topbar-actions">
            <Pill tone="amber">ДЕМО · БЕЗ КРИПТОГРАФИИ</Pill>
            <button
              className="avatar topbar-avatar"
              onClick={() => setScreen("security")}
              aria-label="Открыть настройки безопасности"
            >
              Я
            </button>
          </div>
        </header>

        {notice && (
          <div className="notice" role="status">
            <span>{notice}</span>
            <button onClick={() => setNotice("")} aria-label="Закрыть уведомление">
              ×
            </button>
          </div>
        )}

        {screen === "chats" && (
          <ChatScreen
            chat={activeChat}
            draft={draft}
            setDraft={setDraft}
            sendMessage={() => void sendMessage()}
            chooseAttachment={(file) => void chooseAttachment(file)}
            attachmentInput={attachmentInput}
            openInvite={() => {
              setInviteTab("invite");
              setInviteOpen(true);
            }}
            profileMode={state.profileMode}
          />
        )}

        {screen === "security" && (
          <SecurityScreen
            bridge={bridge}
            incoming={state.relayConfig.incoming}
            outgoing={state.relayConfig.outgoing}
            storageReady={state.storageReady}
            storageError={state.storageError}
          />
        )}

        {screen === "duress" && (
          <DuressScreen
            state={state}
            failure={duressFailure}
            setFailure={setDuressFailure}
            activate={() => void activateDuress()}
            retry={() => void retryDuress()}
          />
        )}
      </main>

      {inviteOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setInviteOpen(false);
          }}
        >
          <section
            className="invite-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="invite-title"
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">ПРИГЛАШЕНИЕ И ПРОВЕРКА</span>
                <h2 id="invite-title">Новый контакт</h2>
              </div>
              <button
                className="icon-button close-button"
                aria-label="Закрыть"
                onClick={() => setInviteOpen(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-tabs" role="tablist">
              <button
                role="tab"
                aria-selected={inviteTab === "invite"}
                className={inviteTab === "invite" ? "modal-tab modal-tab-active" : "modal-tab"}
                onClick={() => setInviteTab("invite")}
              >
                <span className="step-number">1</span>
                Обмен приглашением
              </button>
              <button
                role="tab"
                aria-selected={inviteTab === "sas"}
                className={inviteTab === "sas" ? "modal-tab modal-tab-active" : "modal-tab"}
                onClick={() => setInviteTab("sas")}
              >
                <span className="step-number">2</span>
                Сверка SAS
              </button>
            </div>

            {inviteTab === "invite" ? (
              <div className="invite-content">
                <div className="invite-columns">
                  <div className="qr-card">
                    {invitation ? (
                      <QRCodeSVG value={invitation.link} size={188} level="M" />
                    ) : (
                      <div className="qr-placeholder">
                        <span className="qr-placeholder-symbol">⌗</span>
                        <span>Создайте одноразовый QR-код</span>
                      </div>
                    )}
                    <span className="qr-caption">
                      {invitation ? "Одноразовое демо-приглашение" : "QR появится после генерации"}
                    </span>
                  </div>
                  <div className="invite-details">
                    <div className="section-title-small">ВАШЕ ПРИГЛАШЕНИЕ</div>
                    <p className="muted-copy">
                      Создайте отдельные capabilities для независимой очереди этого контакта.
                    </p>
                    <Button onClick={generateInvitation}>
                      <Icon>✳</Icon>
                      Сгенерировать приглашение
                    </Button>
                    {invitation && (
                      <div className="capability-list">
                        <Capability
                          label="Очередь"
                          value={invitation.queueId}
                          onCopy={() => void copyText(invitation.queueId)}
                        />
                        <Capability
                          label="Чтение"
                          value={invitation.readCapability}
                          onCopy={() => void copyText(invitation.readCapability)}
                        />
                        <Capability
                          label="Запись"
                          value={invitation.writeCapability}
                          onCopy={() => void copyText(invitation.writeCapability)}
                        />
                        <Button
                          variant="secondary"
                          className="full-width"
                          onClick={() => void copyText(invitation.link)}
                        >
                          Скопировать строку приглашения
                        </Button>
                      </div>
                    )}
                  </div>
                </div>
                <div className="invite-divider">
                  <span />
                  <small>ИЛИ ВСТАВЬТЕ ПРИГЛАШЕНИЕ СОБЕСЕДНИКА</small>
                  <span />
                </div>
                <div className="import-row">
                  <input
                    className="text-input"
                    value={inviteName}
                    onChange={(event) => setInviteName(event.target.value)}
                    placeholder="Имя контакта (необязательно)"
                    aria-label="Имя контакта"
                  />
                  <textarea
                    className="text-input invite-input"
                    value={inviteText}
                    onChange={(event) => setInviteText(event.target.value)}
                    placeholder="Вставьте строку приглашения"
                    aria-label="Строка приглашения"
                  />
                  <Button variant="secondary" onClick={importInvitation}>
                    Принять приглашение
                  </Button>
                </div>
                <DemoDisclosure />
              </div>
            ) : (
              <div className="sas-content">
                {activeChat ? (
                  <>
                    <div className={`verification-warning ${activeChat.verified ? "warning-verified" : ""}`}>
                      <span className="warning-icon">{activeChat.verified ? "✓" : "!"}</span>
                      <div>
                        <strong>
                          {activeChat.verified
                            ? "Код сверки отмечен как подтверждённый"
                            : "Сессия UNVERIFIED"}
                        </strong>
                        <span>
                          {activeChat.verified
                            ? "Изменение статуса относится только к демо."
                            : "До сверки кода возможна активная атака посредника (MITM)."}
                        </span>
                      </div>
                    </div>
                    <div className="sas-display">
                      <span className="eyebrow">48-БИТНЫЙ КОД · ДЕМО</span>
                      <div className="sas-hex">{formatSas(activeChat.sasHex)}</div>
                      <div className="sas-words">
                        {sasWordPairs(activeChat.sasHex).map((pair, index) => (
                          <span key={`${pair}-${index}`}>{pair}</span>
                        ))}
                      </div>
                      <div className="sas-icon-grid" aria-label="Визуальная сетка кода">
                        {activeChat.sasHex.split("").map((hex, index) => (
                          <div className="sas-icon-cell" key={`${hex}-${index}`}>
                            <span>{SAS_ICONS[Number.parseInt(hex, 16)]}</span>
                            <small>{hex.toUpperCase()}</small>
                          </div>
                        ))}
                      </div>
                    </div>
                    <label className="sas-confirm-check">
                      <input
                        type="checkbox"
                        checked={sasChecked}
                        onChange={(event) => setSasChecked(event.target.checked)}
                      />
                      <span>Я сверил код с собеседником лично</span>
                    </label>
                    <Button
                      className="full-width"
                      disabled={!sasChecked || activeChat.verified}
                      onClick={() => {
                        bridge.confirmSas(activeChat.id);
                        setNotice("Статус отмечен VERIFIED в интерактивном демо.");
                      }}
                    >
                      {activeChat.verified ? "VERIFIED · подтверждено в демо" : "Подтвердить (VERIFIED)"}
                    </Button>
                    <DemoDisclosure />
                  </>
                ) : (
                  <div className="empty-state">
                    <div className="empty-state-icon">⌑</div>
                    <h3>Сначала выберите контакт</h3>
                    <p>Приглашение создаёт отдельную демонстрационную сессию.</p>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function Capability({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: () => void;
}) {
  return (
    <div className="capability">
      <span>{label}</span>
      <code>{value.slice(0, 14)}…</code>
      <button onClick={onCopy} aria-label={`Скопировать capability ${label}`} title="Скопировать">
        ⧉
      </button>
    </div>
  );
}

function DemoDisclosure() {
  return (
    <div className="demo-disclosure">
      <span className="disclosure-icon">i</span>
      <span>
        Это интерактивный прототип: QR, приглашение и SAS синтетические. Rust handshake
        и криптографическое подтверждение здесь не выполняются.
      </span>
    </div>
  );
}

function ChatScreen({
  chat,
  draft,
  setDraft,
  sendMessage,
  chooseAttachment,
  attachmentInput,
  openInvite,
  profileMode,
}: {
  chat: Chat | null;
  draft: string;
  setDraft: (value: string) => void;
  sendMessage: () => void;
  chooseAttachment: (file?: File) => void;
  attachmentInput: RefObject<HTMLInputElement | null>;
  openInvite: () => void;
  profileMode: "real" | "pending" | "decoy";
}) {
  const messagesEnd = useRef<HTMLDivElement>(null);
  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [chat?.messages.length]);

  if (profileMode === "pending") {
    return (
      <div className="pending-screen">
        <div className="pending-lock">⌑</div>
        <h2>Профиль ожидает очистки</h2>
        <p>
          Постоянное удаление обёртки реального ключа ещё не подтверждено. Демо-клиент
          скрывает содержимое и не активирует нейтральный профиль до подтверждения.
        </p>
      </div>
    );
  }

  if (!chat) {
    return (
      <div className="empty-state chat-empty">
        <div className="empty-state-icon">◷</div>
        <h3>Здесь пока тихо</h3>
        <p>Создайте одноразовое приглашение, чтобы начать диалог.</p>
        <Button onClick={openInvite}>Создать приглашение</Button>
      </div>
    );
  }

  return (
    <div className="chat-layout">
      <div className="chat-heading">
        <div className="chat-contact">
          <div className="avatar avatar-large">{chat.name.slice(0, 1).toUpperCase()}</div>
          <div>
            <h1>{chat.name}</h1>
            <div className="contact-status">
              <span className={`status-dot ${chat.verified ? "status-dot-verified" : ""}`} />
              {chat.verified ? "Контакт подтверждён" : "UNVERIFIED · требуется сверка SAS"}
            </div>
          </div>
        </div>
        <div className="chat-actions">
          {!chat.verified && (
            <Button
              variant="secondary"
              onClick={openInvite}
              className="verify-shortcut"
            >
              Сверить SAS
            </Button>
          )}
          <button
            className="icon-button more-button"
            aria-label="Открыть проверку приглашения и SAS"
            onClick={openInvite}
          >
            ···
          </button>
        </div>
      </div>

      {!chat.verified && (
        <div className="mitm-inline-warning">
          <span>!</span>
          <div>
            <strong>Не подтверждённая сессия</strong>
            <span>До личной сверки SAS возможен активный MITM.</span>
          </div>
          <button onClick={openInvite}>Проверить</button>
        </div>
      )}

      <div className="messages-area">
        <div className="day-divider"><span>СЕГОДНЯ</span></div>
        {chat.messages.map((message) => (
          <article
            className={`message-row ${message.direction === "outgoing" ? "message-row-outgoing" : ""}`}
            key={message.id}
          >
            {message.direction === "incoming" && (
              <div className="message-avatar">{chat.name.slice(0, 1).toUpperCase()}</div>
            )}
            <div className={`message-bubble ${message.direction === "outgoing" ? "message-bubble-outgoing" : ""}`}>
              {message.attachment && (
                <figure className="message-attachment">
                  <img src={message.attachment.previewUrl} alt="Очищенное вложение" />
                  <figcaption>
                    <span className="attachment-check">✓</span>
                    JPEG/PNG · повторное кодирование в демо
                  </figcaption>
                </figure>
              )}
              {message.body && <p>{message.body}</p>}
              <div className="message-meta">
                <span>{formatTime(message.sentAt)}</span>
                <span className="delivery-status" title="Демо-статус, не результат реального шифрования">
                  {deliveryLabel(message)}
                </span>
              </div>
            </div>
          </article>
        ))}
        <div ref={messagesEnd} />
      </div>

      <div className="composer-wrap">
        <div className="composer-note">
          <span>✳</span>
          JPEG/PNG повторно кодируются в браузере для удаления метаданных перед демо-отправкой.
        </div>
        <div className="composer">
          <input
            ref={attachmentInput}
            className="visually-hidden"
            type="file"
            accept="*/*"
            aria-label="Выбрать вложение"
            onChange={(event) => chooseAttachment(event.target.files?.[0])}
          />
          <button
            className="attachment-button"
            aria-label="Прикрепить файл"
            title="JPEG/PNG; неподдерживаемые форматы будут отклонены"
            onClick={() => attachmentInput.current?.click()}
          >
            +
          </button>
          <textarea
            rows={1}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
              }
            }}
            placeholder="Напишите сообщение…"
            aria-label="Текст сообщения"
          />
          <button
            className="send-button"
            onClick={sendMessage}
            disabled={!draft.trim()}
            aria-label="Отправить сообщение"
          >
            ↗
          </button>
        </div>
        <div className="composer-footer">
          <span><kbd>Enter</kbd> отправить · <kbd>Shift + Enter</kbd> новая строка</span>
          <span>Сообщения отображаются только в демо-памяти</span>
        </div>
      </div>
    </div>
  );
}

function SecurityScreen({
  bridge,
  incoming,
  outgoing,
  storageReady,
  storageError,
}: {
  bridge: DemoClientBridge;
  incoming: string;
  outgoing: string;
  storageReady: boolean;
  storageError: string | null;
}) {
  const [incomingDraft, setIncomingDraft] = useState(incoming);
  const [outgoingDraft, setOutgoingDraft] = useState(outgoing);
  const [torEnabled, setTorEnabled] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setIncomingDraft(incoming);
    setOutgoingDraft(outgoing);
  }, [incoming, outgoing]);

  return (
    <div className="settings-page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">КОНТРОЛЬ ПРИВАТНОСТИ</span>
          <h1>Безопасность и самопроверка</h1>
          <p>Параметры показывают целевую архитектуру. Сеть и криптография в этом демо не подключены.</p>
        </div>
        <Pill tone="amber">ДЕМО-КОНФИГУРАЦИЯ</Pill>
      </div>

      <div className="settings-grid">
        <Panel className="relay-panel">
          <div className="panel-heading">
            <div className="panel-icon green-icon">⇄</div>
            <div>
              <h2>Маршрутизация релея</h2>
              <p>Раздельные адреса входящей и исходящей очередей</p>
            </div>
          </div>
          <label className="field-label" htmlFor="incoming-relay">ВХОДЯЩЕЕ РЕЛЕ</label>
          <input
            id="incoming-relay"
            className="text-input"
            value={incomingDraft}
            onChange={(event) => {
              setIncomingDraft(event.target.value);
              setSaved(false);
            }}
            spellCheck={false}
          />
          <label className="field-label" htmlFor="outgoing-relay">ИСХОДЯЩЕЕ РЕЛЕ</label>
          <input
            id="outgoing-relay"
            className="text-input"
            value={outgoingDraft}
            onChange={(event) => {
              setOutgoingDraft(event.target.value);
              setSaved(false);
            }}
            spellCheck={false}
          />
          <div className="relay-actions">
            <Button
              variant="secondary"
              onClick={() => {
                bridge.setRelayConfig({ incoming: incomingDraft, outgoing: outgoingDraft });
                setSaved(true);
              }}
            >
              Сохранить адреса
            </Button>
            {saved && <span className="saved-label">Сохранено локально в состоянии демо</span>}
          </div>
          <div className="setting-divider" />
          <div className="setting-row">
            <div>
              <strong>Маршрут через Tor SOCKS5</strong>
              <span>127.0.0.1:9050 · настройка не применяется в браузерном демо</span>
            </div>
            <button
              className={`toggle ${torEnabled ? "toggle-on" : ""}`}
              role="switch"
              aria-checked={torEnabled}
              onClick={() => setTorEnabled((value) => !value)}
            >
              <span />
            </button>
          </div>
        </Panel>

        <Panel className="profile-panel">
          <div className="panel-heading">
            <div className="panel-icon violet-icon">⌑</div>
            <div>
              <h2>Параметры протокола</h2>
              <p>Самопроверка ограничений crypto-core</p>
            </div>
          </div>
          <div className="spec-list">
            <SpecRow label="Паддинг пакета" value="1 / 4 / 16 KiB" icon="▤" />
            <SpecRow label="Skipped message keys" value="лимит 2 000" icon="⟳" />
            <SpecRow label="Медиа" value="только JPEG / PNG re-encode" icon="▧" />
            <SpecRow label="Очереди" value="отдельные на каждый контакт" icon="⇄" />
            <SpecRow
              label="Состояние локального хранилища"
              value={storageError ? "недоступно" : storageReady ? "IndexedDB · демо" : "проверка…"}
              icon="⌑"
            />
          </div>
        </Panel>

        <Panel className="limits-panel">
          <div className="panel-heading">
            <div className="panel-icon amber-icon">!</div>
            <div>
              <h2>Границы защиты</h2>
              <p>Известные ограничения и честные гарантии</p>
            </div>
          </div>
          <div className="limit-item">
            <span className="limit-marker">01</span>
            <div><strong>MITM до сверки</strong><p>Сессия остаётся UNVERIFIED, пока собеседники лично не сверят SAS или QR.</p></div>
          </div>
          <div className="limit-item">
            <span className="limit-marker">02</span>
            <div><strong>Crypto-shredding</strong><p>Удаление key wrap не доказывает физическую перезапись SSD, журналов ОС или резервных копий.</p></div>
          </div>
          <div className="limit-item">
            <span className="limit-marker">03</span>
            <div><strong>Защита endpoint</strong><p>Браузерное демо не шифрует IndexedDB и не блокирует снимки экрана или дампы памяти.</p></div>
          </div>
        </Panel>

        <Panel className="check-panel">
          <div className="panel-heading">
            <div className="panel-icon blue-icon">✓</div>
            <div>
              <h2>Самопроверка сборки</h2>
              <p>Только клиентская демонстрационная среда</p>
            </div>
          </div>
          <div className="check-list">
            <CheckRow label="Внешние CDN-скрипты" value="не используются" good />
            <CheckRow label="Телеметрия" value="отсутствует" good />
            <CheckRow label="Реальная криптография" value="не подключена" />
            <CheckRow label="Сетевой relay" value="не подключён" />
            <CheckRow label="Argon2id и шифрование БД" value="не выполняются" />
          </div>
          {storageError && <p className="error-copy">{storageError}</p>}
        </Panel>
      </div>
    </div>
  );
}

function SpecRow({ label, value, icon }: { label: string; value: string; icon: string }) {
  return (
    <div className="spec-row">
      <span className="spec-icon">{icon}</span>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function CheckRow({
  label,
  value,
  good = false,
}: {
  label: string;
  value: string;
  good?: boolean;
}) {
  return (
    <div className="check-row">
      <span className={`check-mark ${good ? "check-mark-good" : ""}`}>{good ? "✓" : "–"}</span>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function DuressScreen({
  state,
  failure,
  setFailure,
  activate,
  retry,
}: {
  state: ReturnType<DemoClientBridge["getSnapshot"]>;
  failure: boolean;
  setFailure: (value: boolean) => void;
  activate: () => void;
  retry: () => void;
}) {
  const isPending = state.duressState === "DURESS_PENDING_CLEANUP";
  const isActive = state.duressState === "ACTIVE";
  const inspection = state.storageInspection;

  return (
    <div className="settings-page duress-page">
      <div className="page-intro">
        <div>
          <span className="eyebrow">ENDPOINT · ЛОКАЛЬНЫЙ КОНТРАКТ</span>
          <h1>Тревожный профиль</h1>
          <p>Демо-путь проверяет обязательное подтверждение удаления постоянной обёртки.</p>
        </div>
        <Pill tone={isActive ? "green" : isPending ? "amber" : "neutral"}>
          {state.duressState}
        </Pill>
      </div>

      <Panel className="duress-hero">
        <div className={`duress-emblem ${isActive ? "duress-emblem-active" : isPending ? "duress-emblem-pending" : ""}`}>
          {isActive ? "✓" : isPending ? "…" : "◉"}
        </div>
        <div className="duress-copy">
          <span className="eyebrow">СОСТОЯНИЕ ПРОФИЛЯ</span>
          <h2>
            {isActive
              ? "Нейтральный демо-профиль активен"
              : isPending
                ? "Ожидается подтверждение удаления"
                : "Основной демо-профиль активен"}
          </h2>
          <p>
            {isActive
              ? "В IndexedDB-демо-маркерах реальная обёртка отсутствует. Это подтверждение транзакции, а не физической очистки носителя."
              : isPending
                ? "Приложение скрывает содержимое основного профиля и не открывает decoy, пока storage-adapter не подтвердит удаление."
                : "При duress немедленно скрывается содержимое сессии, сохраняется pending-состояние, затем удаляется реальный key-wrap маркер."}
          </p>
        </div>
        <div className="duress-status-art">
          <div className="status-ring"><span /></div>
          <span>{isActive ? "ЗАЩИТНЫЙ ПРОФИЛЬ" : isPending ? "ОЧИСТКА НЕ ПОДТВЕРЖДЕНА" : "ГОТОВ К ДЕМО"}</span>
        </div>
      </Panel>

      <div className="duress-grid">
        <Panel className="duress-action-panel">
          <div className="panel-heading">
            <div className="panel-icon red-icon">⌑</div>
            <div>
              <h2>Проверить сценарий</h2>
              <p>Нажмите, чтобы пройти демонстрационный контракт</p>
            </div>
          </div>
          <div className="duress-flow">
            <FlowStep number="1" title="Очистить состояние в RAM" description="Демо мгновенно скрывает сообщения; это не доказывает zeroization JS-памяти." />
            <FlowStep number="2" title="Зафиксировать pending" description="DURESS_PENDING_CLEANUP записывается до запроса удаления." />
            <FlowStep number="3" title="Удалить key-wrap маркер" description="Адаптер ждёт commit IndexedDB и проверяет отсутствие записи." />
            <FlowStep number="4" title="Открыть decoy" description="Нейтральный профиль доступен только после полученного receipt." />
          </div>
          {!isActive && !isPending && (
            <label className="failure-toggle">
              <input
                type="checkbox"
                checked={failure}
                onChange={(event) => setFailure(event.target.checked)}
              />
              <span>Сымитировать сбой удаления при первом запуске</span>
            </label>
          )}
          {isPending ? (
            <Button className="full-width" onClick={retry}>Повторить очистку</Button>
          ) : isActive ? (
            <Button variant="secondary" className="full-width" onClick={retry}>
              Проверить состояние хранения
            </Button>
          ) : (
            <Button variant="danger" className="full-width" onClick={activate}>
              Запустить тревожный сценарий (демо)
            </Button>
          )}
          {isPending && (
            <div className="pending-contract">
              <strong>Decoy не активирован.</strong>
              <span>Попробуйте повторить удаление после устранения ошибки хранилища.</span>
            </div>
          )}
        </Panel>

        <Panel className="storage-panel">
          <div className="panel-heading">
            <div className="panel-icon green-icon">▤</div>
            <div>
              <h2>Storage-adapter</h2>
              <p>Состояние демонстрационных маркеров IndexedDB</p>
            </div>
          </div>
          <div className="storage-state">
            <span>Постоянное состояние</span>
            <Pill tone={isActive ? "green" : isPending ? "amber" : "neutral"}>
              {inspection?.state ?? (state.storageReady ? "NORMAL" : "ПРОВЕРКА")}
            </Pill>
          </div>
          <div className="storage-state">
            <span>Real key-wrap маркер</span>
            <strong className={inspection?.realKeyWrapPresent ? "text-danger" : "text-good"}>
              {inspection ? (inspection.realKeyWrapPresent ? "присутствует" : "отсутствует") : "—"}
            </strong>
          </div>
          <div className="storage-state">
            <span>Decoy marker</span>
            <strong>{inspection ? (inspection.decoyKeyWrapPresent ? "присутствует" : "отсутствует") : "—"}</strong>
          </div>
          <div className="storage-receipt">
            <span className="receipt-icon">✓</span>
            <p>
              Receipt выдаётся только после завершения IndexedDB-транзакции и read-back проверки
              отсутствия маркера. Повторный вызов после сбоя идемпотентен.
            </p>
          </div>
        </Panel>
      </div>

      <div className="boundary-note">
        <span className="boundary-icon">i</span>
        <div>
          <strong>Граница гарантий</strong>
          <p>
            Реальный клиент может обеспечить crypto-shredding только в пределах ключевого материала
            и успешного удаления его постоянной обёртки. Ни Rust-контракт, ни браузерное подтверждение
            не гарантируют перезапись секторов SSD, журналов ОС, swap-файлов или системных бэкапов.
            Здесь хранятся лишь маркеры без ключей.
          </p>
        </div>
      </div>
    </div>
  );
}

function FlowStep({
  number,
  title,
  description,
}: {
  number: string;
  title: string;
  description: string;
}) {
  return (
    <div className="flow-step">
      <span className="flow-number">{number}</span>
      <div><strong>{title}</strong><p>{description}</p></div>
    </div>
  );
}
