// The Isolation agent view (PLAN V2) — one chat window onto ONE agent, served by the
// doorman at /v/<viewId>/. The agent has a single conversation; every window onto it
// (this view in N tabs, other views of the same agent) polls the same thread and
// converges. Sending boots a lazy/stopped agent — a message is an implicit start.
import "./agent.css";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const threadEl = $("thread");
const scrollEl = $("scroll");
const emptyEl = $("empty");
const inputEl = $("input") as unknown as HTMLTextAreaElement;
const sendEl = $("send") as unknown as HTMLButtonElement;
const nameEl = $("agent-name");
const metaEl = $("agent-meta");
const dotEl = $("status-dot");
const toggleEl = $("toggle") as unknown as HTMLButtonElement;

interface Message {
  role: "user" | "assistant";
  text: string;
  ts: number;
  from?: string;
}

interface AgentInfo {
  name: string;
  harness: string;
  model: string | null;
  status: "idle" | "running" | "stopped";
}

let status: AgentInfo["status"] = "idle";
let rendered = 0; // messages already in the DOM
let sending = false;
let lastError = "";

const errBar = document.createElement("div");
errBar.id = "error-bar";
document.body.append(errBar);

function showError(text: string): void {
  lastError = text;
  errBar.textContent = text;
}
function clearError(): void {
  if (!lastError) return;
  lastError = "";
  errBar.textContent = "";
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`api/${path}`, init);
  const body = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
  return body;
}

// --- header ---------------------------------------------------------------------

function renderHeader(a: AgentInfo): void {
  status = a.status;
  nameEl.textContent = a.name;
  document.title = `${a.name} — Isolation`;
  metaEl.textContent = a.model ? `${a.harness} · ${a.model}` : a.harness;
  dotEl.className = `dot ${a.status}`;
  toggleEl.hidden = false;
  toggleEl.textContent = a.status === "stopped" ? "Start" : "Stop";
  $("empty-line").textContent = `Send the first message to ${a.name}`;
}

toggleEl.onclick = async () => {
  try {
    await api(status === "stopped" ? "start" : "stop", { method: "POST" });
    await refresh();
  } catch (e) {
    showError((e as Error).message);
  }
};

// --- thread ---------------------------------------------------------------------

const atBottom = (): boolean => scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight < 60;
const scrollDown = (): void => {
  scrollEl.scrollTop = scrollEl.scrollHeight;
};

function bubble(m: Message): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = `msg ${m.role}`;
  const b = document.createElement("div");
  b.className = "bubble";
  b.textContent = m.text;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  wrap.append(b, meta);
  return wrap;
}

let pendingEl: HTMLElement | undefined;

function showPending(): void {
  if (pendingEl) return;
  pendingEl = document.createElement("div");
  pendingEl.className = "msg assistant pending";
  const b = document.createElement("div");
  b.className = "bubble";
  b.textContent = "thinking…";
  pendingEl.append(b);
  threadEl.append(pendingEl);
  scrollDown();
}
function hidePending(): void {
  pendingEl?.remove();
  pendingEl = undefined;
}

function renderMessages(messages: Message[]): void {
  emptyEl.hidden = messages.length > 0 || sending;
  if (messages.length < rendered) {
    // The thread shrank (memory cleared / other window's failed turn rolled back) — rebuild.
    threadEl.replaceChildren();
    rendered = 0;
  }
  if (messages.length === rendered) return;
  const stick = atBottom();
  const frag = document.createDocumentFragment();
  for (const m of messages.slice(rendered)) frag.append(bubble(m));
  hidePending();
  threadEl.append(frag);
  if (sending) showPending();
  rendered = messages.length;
  if (stick) scrollDown();
}

// --- send -----------------------------------------------------------------------

async function send(): Promise<void> {
  const text = inputEl.value.trim();
  if (!text || sending) return;
  sending = true;
  inputEl.value = "";
  autoGrow();
  sendEl.disabled = true;
  renderMessages([...lastMessages, { role: "user", text, ts: Date.now() }]);
  lastMessages.push({ role: "user", text, ts: Date.now() });
  showPending();
  try {
    await api("messages", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    clearError();
  } catch (e) {
    showError(`send failed: ${(e as Error).message}`);
  } finally {
    sending = false;
    sendEl.disabled = false;
    hidePending();
    await refresh();
    inputEl.focus();
  }
}

sendEl.onclick = () => void send();
inputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    void send();
  }
});
function autoGrow(): void {
  inputEl.style.height = "auto";
  inputEl.style.height = `${Math.min(inputEl.scrollHeight, 140)}px`;
}
inputEl.addEventListener("input", autoGrow);

// --- poll -----------------------------------------------------------------------

let lastMessages: Message[] = [];

async function refresh(): Promise<void> {
  try {
    const [agent, thread] = await Promise.all([
      api<AgentInfo & { id: string }>("agent"),
      api<{ status: AgentInfo["status"]; messages: Message[] }>("messages"),
    ]);
    renderHeader(agent);
    lastMessages = thread.messages;
    renderMessages(thread.messages);
    clearError();
  } catch (e) {
    showError((e as Error).message);
  }
}

// Strip the bootstrap token from the address bar (the doorman promoted it to a cookie).
const u = new URL(location.href);
if (u.searchParams.has("token")) {
  u.searchParams.delete("token");
  history.replaceState(null, "", u);
}

void refresh().then(scrollDown);
setInterval(() => {
  if (!document.hidden && !sending) void refresh();
}, 2500);
inputEl.focus();
