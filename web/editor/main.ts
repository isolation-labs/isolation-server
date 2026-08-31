// The Isolation code view (PLAN V1) — a first-party Monaco editor over the doorman's
// execd-backed file API. Served at /v/<viewId>/ by isolation-server itself: no process
// in the sandbox, no code-server. Direct links carry the location in the QUERY
// (?file=<workspace-relative-path>&line=<n>) so the doorman's routing stays untouched,
// and a mounted view navigates in place on a `isolation:open` postMessage instead of
// reloading.
import * as monaco from "monaco-editor";
import "./editor.css";

// Monaco's language smarts run in a worker; we bundle the base worker next to main.js.
(self as unknown as { MonacoEnvironment: unknown }).MonacoEnvironment = {
  getWorker: () => new Worker(new URL("./editor.worker.js", location.href)),
};

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const treeEl = $("tree");
const tabsEl = $("tabs");
const emptyEl = $("empty-state");
const statusPath = $("status-path");
const statusLang = $("status-lang");
const statusMsg = $("status-msg");

// --- api ------------------------------------------------------------------------

async function apiList(path: string): Promise<{ name: string; dir: boolean }[]> {
  const r = await fetch(`api/list?path=${encodeURIComponent(path)}`);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error ?? `HTTP ${r.status}`);
  return ((await r.json()) as { entries: { name: string; dir: boolean }[] }).entries;
}

async function apiRead(path: string): Promise<ArrayBuffer> {
  const r = await fetch(`api/file?path=${encodeURIComponent(path)}`);
  if (!r.ok) throw new Error(((await r.json().catch(() => ({}))) as { error?: string }).error ?? `HTTP ${r.status}`);
  return r.arrayBuffer();
}

async function apiSave(path: string, content: string): Promise<void> {
  const r = await fetch(`api/file?path=${encodeURIComponent(path)}`, { method: "PUT", body: content });
  if (!r.ok) throw new Error(((await r.json().catch(() => ({}))) as { error?: string }).error ?? `HTTP ${r.status}`);
}

// --- status ---------------------------------------------------------------------

let msgTimer: number | undefined;
function flash(text: string, isError = false): void {
  statusMsg.textContent = text;
  statusMsg.classList.toggle("error", isError);
  if (msgTimer) clearTimeout(msgTimer);
  if (!isError) msgTimer = window.setTimeout(() => (statusMsg.textContent = ""), 2500);
}

// --- editor ---------------------------------------------------------------------

monaco.editor.defineTheme("isolation-dark", {
  base: "vs-dark",
  inherit: true,
  rules: [],
  colors: {
    "editor.background": "#0b0d10",
    "editor.lineHighlightBackground": "#12161c",
    "editorLineNumber.foreground": "#3d4652",
    "editorLineNumber.activeForeground": "#9aa4b2",
    "editorGutter.background": "#0b0d10",
    "editorWidget.background": "#101318",
    "editorWidget.border": "#232a33",
    "focusBorder": "#232a33",
    "scrollbarSlider.background": "#232a3366",
    "scrollbarSlider.hoverBackground": "#232a33aa",
  },
});

const editor = monaco.editor.create($("editor"), {
  theme: "isolation-dark",
  automaticLayout: true,
  fontSize: 13,
  minimap: { enabled: false },
  scrollBeyondLastLine: false,
  renderWhitespace: "none",
  smoothScrolling: true,
  padding: { top: 8 },
  stickyScroll: { enabled: false },
});

interface Tab {
  path: string;
  model: monaco.editor.ITextModel;
  savedVersion: number;
  viewState: monaco.editor.ICodeEditorViewState | null;
}

const tabs = new Map<string, Tab>();
let active: Tab | undefined;

const isDirty = (t: Tab): boolean => t.model.getAlternativeVersionId() !== t.savedVersion;

function renderTabs(): void {
  tabsEl.replaceChildren(
    ...[...tabs.values()].map((t) => {
      const el = document.createElement("div");
      el.className = `tab${t === active ? " active" : ""}${isDirty(t) ? " dirty" : ""}`;
      el.setAttribute("role", "tab");
      el.title = t.path;
      const name = document.createElement("span");
      name.textContent = t.path.split("/").pop() ?? t.path;
      const close = document.createElement("button");
      close.className = "close";
      close.title = "Close";
      close.innerHTML = `<span class="x">&times;</span>`;
      close.onclick = (e) => {
        e.stopPropagation();
        closeTab(t);
      };
      el.onclick = () => activate(t);
      el.append(name, close);
      return el;
    }),
  );
}

function syncUrl(): void {
  const u = new URL(location.href);
  u.searchParams.delete("token"); // promoted to a cookie by the doorman on first load
  u.searchParams.delete("line");
  if (active) u.searchParams.set("file", active.path);
  else u.searchParams.delete("file");
  history.replaceState(null, "", u);
}

function activate(t: Tab): void {
  if (active && active !== t) active.viewState = editor.saveViewState();
  active = t;
  editor.setModel(t.model);
  if (t.viewState) editor.restoreViewState(t.viewState);
  emptyEl.classList.add("hidden");
  statusPath.textContent = t.path;
  statusLang.textContent = t.model.getLanguageId();
  renderTabs();
  markActiveTreeNode();
  syncUrl();
  editor.focus();
}

function closeTab(t: Tab): void {
  if (isDirty(t) && !confirm(`${t.path} has unsaved changes. Close anyway?`)) return;
  tabs.delete(t.path);
  t.model.dispose();
  if (active === t) {
    active = [...tabs.values()].pop();
    if (active) activate(active);
    else {
      editor.setModel(null);
      emptyEl.classList.remove("hidden");
      statusPath.textContent = "";
      statusLang.textContent = "";
      renderTabs();
      markActiveTreeNode();
      syncUrl();
    }
  } else renderTabs();
}

async function openFile(path: string, line?: number): Promise<void> {
  let t = tabs.get(path);
  if (!t) {
    let bytes: ArrayBuffer;
    try {
      bytes = await apiRead(path);
    } catch (e) {
      flash(`open failed: ${(e as Error).message}`, true);
      return;
    }
    const head = new Uint8Array(bytes.slice(0, 8192));
    if (head.includes(0)) {
      flash(`${path.split("/").pop()} looks binary — not opening`, true);
      return;
    }
    const text = new TextDecoder().decode(bytes);
    const model = monaco.editor.createModel(text, undefined, monaco.Uri.file(`/${path}`));
    t = { path, model, savedVersion: model.getAlternativeVersionId(), viewState: null };
    model.onDidChangeContent(() => renderTabs());
    tabs.set(path, t);
  }
  activate(t);
  if (line && line > 0) {
    editor.revealLineInCenter(line);
    editor.setPosition({ lineNumber: line, column: 1 });
  }
}

async function save(): Promise<void> {
  const t = active;
  if (!t || !isDirty(t)) return;
  const version = t.model.getAlternativeVersionId();
  try {
    await apiSave(t.path, t.model.getValue());
    t.savedVersion = version;
    renderTabs();
    flash("Saved");
  } catch (e) {
    flash(`save failed: ${(e as Error).message}`, true);
  }
}

editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => void save());
// Swallow the browser's save dialog when focus sits outside the editor too.
window.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "s") {
    e.preventDefault();
    void save();
  }
});
window.addEventListener("beforeunload", (e) => {
  if ([...tabs.values()].some(isDirty)) e.preventDefault();
});

// --- file tree ------------------------------------------------------------------
// Lazy: a directory lists on first expand. Each node keeps its children container.

const nodeByPath = new Map<string, HTMLElement>();

function markActiveTreeNode(): void {
  for (const [p, el] of nodeByPath) el.classList.toggle("active", p === active?.path);
}

function makeNode(path: string, name: string, dir: boolean, depth: number): HTMLElement {
  const wrap = document.createElement("div");
  const row = document.createElement("div");
  row.className = `node${dir ? " dir" : ""}`;
  row.style.paddingLeft = `${8 + depth * 12}px`;
  row.setAttribute("role", "treeitem");
  const twist = document.createElement("span");
  twist.className = "twist";
  twist.textContent = dir ? "▸" : "";
  const icon = document.createElement("span");
  icon.className = "icon";
  icon.textContent = dir ? "▦" : "□";
  const label = document.createElement("span");
  label.className = "name";
  label.textContent = name;
  row.append(twist, icon, label);
  wrap.append(row);
  if (dir) {
    let kids: HTMLElement | undefined;
    let expanded = false;
    row.onclick = async () => {
      expanded = !expanded;
      twist.textContent = expanded ? "▾" : "▸";
      if (!kids) {
        kids = document.createElement("div");
        wrap.append(kids);
        await fillDir(kids, path, depth + 1);
      }
      kids.style.display = expanded ? "" : "none";
    };
  } else {
    nodeByPath.set(path, row);
    row.onclick = () => void openFile(path);
  }
  return wrap;
}

async function fillDir(container: HTMLElement, path: string, depth: number): Promise<void> {
  try {
    const entries = await apiList(path);
    container.replaceChildren(...entries.map((e) => makeNode(path ? `${path}/${e.name}` : e.name, e.name, e.dir, depth)));
    if (!entries.length) {
      const note = document.createElement("div");
      note.className = "tree-note";
      note.textContent = "(empty)";
      container.replaceChildren(note);
    }
  } catch (e) {
    const note = document.createElement("div");
    note.className = "tree-note";
    note.textContent = `listing failed: ${(e as Error).message}`;
    container.replaceChildren(note);
  }
}

async function loadTree(): Promise<void> {
  nodeByPath.clear();
  await fillDir(treeEl, "", 0);
  markActiveTreeNode();
}

$("refresh").onclick = () => void loadTree();

// --- deep links + navigation ----------------------------------------------------

// `isolation:open` lets the surrounding SPA (or anything embedding the view) steer a
// mounted editor to a file/line without a reload. Payload only — no capability beyond
// what the view token already grants — so no origin gate is needed.
window.addEventListener("message", (e) => {
  const d = e.data as { type?: string; file?: string; line?: number } | null;
  if (d && d.type === "isolation:open" && typeof d.file === "string") {
    void openFile(d.file, typeof d.line === "number" ? d.line : undefined);
  }
});

// A small imperative handle for whatever embeds the view (same-origin scripting or
// tests): steer the mounted editor without the postMessage hop.
Object.assign(window as object, { isolationCodeView: { open: openFile, save, editor } });

const boot = new URL(location.href).searchParams;
void loadTree().then(() => {
  const file = boot.get("file");
  const line = Number(boot.get("line") ?? "") || undefined;
  if (file) void openFile(file, line);
  else syncUrl(); // still strip the token from the address bar
});
