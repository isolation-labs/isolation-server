// The Isolation git view (PLAN V3) — one repo's working diff, VS-Code-panel-shaped:
// status list, stage/unstage/discard, per-file diff, commit. Served by the doorman;
// every operation is an execd git command. File names deep-link into the V1 code view
// through the surrounding SPA (`isolation:open-file` postMessage to the parent).
import "./git.css";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const repoPick = $("repo-pick") as unknown as HTMLSelectElement;
const branchEl = $("branch");
const abEl = $("aheadbehind");
const stagedList = $("staged-list");
const changesList = $("changes-list");
const stagedCount = $("staged-count");
const changesCount = $("changes-count");
const cleanNote = $("clean-note");
const commitMsg = $("commit-msg") as unknown as HTMLTextAreaElement;
const commitBtn = $("commit-btn") as unknown as HTMLButtonElement;
const diffEl = $("diff");
const diffHead = $("diff-head");
const diffFile = $("diff-file");
const diffEmpty = $("diff-empty");

interface StatusFile {
  path: string;
  index: string;
  work: string;
  renamedFrom?: string;
}

let repo = new URL(location.href).searchParams.get("repo") ?? "";
let pinned = false;
let selected: { path: string; staged: boolean } | undefined;
let lastSig = "";
let firstHunkLine: number | undefined;

const errBar = document.createElement("div");
errBar.id = "error-bar";
document.body.append(errBar);
const showError = (t: string): void => void (errBar.textContent = t);
const clearError = (): void => void (errBar.textContent = "");

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const sep = path.includes("?") ? "&" : "?";
  const r = await fetch(`api/${path}${repo ? `${sep}repo=${encodeURIComponent(repo)}` : ""}`, init);
  const body = (await r.json().catch(() => ({}))) as T & { error?: string };
  if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
  return body;
}

// --- repo picker ----------------------------------------------------------------

async function loadRepos(): Promise<void> {
  const out = await api<{ repos: string[]; pinned: string | null }>("repos");
  pinned = out.pinned !== null;
  if (pinned) {
    repo = out.pinned as string;
    repoPick.hidden = true;
    return;
  }
  const repos = out.repos.length ? out.repos : [""];
  if (!repos.includes(repo)) repo = repos[0];
  repoPick.hidden = repos.length < 2;
  repoPick.replaceChildren(
    ...repos.map((r) => {
      const o = document.createElement("option");
      o.value = r;
      o.textContent = r || "/workspace";
      o.selected = r === repo;
      return o;
    }),
  );
}

repoPick.onchange = () => {
  repo = repoPick.value;
  const u = new URL(location.href);
  if (repo) u.searchParams.set("repo", repo);
  else u.searchParams.delete("repo");
  history.replaceState(null, "", u);
  selected = undefined;
  lastSig = "";
  renderDiffEmpty();
  void refresh(true);
};

// --- status ---------------------------------------------------------------------

const stagedHalf = (f: StatusFile): boolean => f.index !== " " && f.index !== "?";
const workHalf = (f: StatusFile): boolean => f.work !== " ";
const letter = (c: string): string => (c === "?" ? "U" : c);

function row(f: StatusFile, staged: boolean): HTMLElement {
  const el = document.createElement("div");
  const code = letter(staged ? f.index : f.work === "?" ? "U" : f.work);
  el.className = `row${selected && selected.path === f.path && selected.staged === staged ? " active" : ""}`;
  el.title = f.renamedFrom ? `${f.renamedFrom} → ${f.path}` : f.path;
  const st = document.createElement("span");
  st.className = `st ${code}`;
  st.textContent = code;
  const name = document.createElement("span");
  name.className = "fname";
  name.textContent = f.path.split("/").pop() ?? f.path;
  const dir = document.createElement("span");
  dir.className = "fdir";
  dir.textContent = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : "";
  const acts = document.createElement("span");
  acts.className = "acts";
  const btn = (label: string, title: string, danger: boolean, onAct: () => void) => {
    const b = document.createElement("button");
    b.textContent = label;
    b.title = title;
    if (danger) b.className = "danger";
    b.onclick = (e) => {
      e.stopPropagation();
      onAct();
    };
    return b;
  };
  if (staged) acts.append(btn("−", "Unstage", false, () => void op("unstage", f.path)));
  else {
    acts.append(
      btn("⟲", "Discard changes", true, () => {
        if (confirm(`Discard changes to ${f.path}? This can't be undone.`)) void op("discard", f.path);
      }),
      btn("+", "Stage", false, () => void op("stage", f.path)),
    );
  }
  el.append(st, name, dir, acts);
  el.onclick = () => void showDiff(f.path, staged);
  return el;
}

async function refresh(force = false): Promise<void> {
  try {
    const s = await api<{ branch: string; ahead: number; behind: number; files: StatusFile[] }>("status");
    clearError();
    const sig = JSON.stringify(s);
    if (!force && sig === lastSig) return;
    lastSig = sig;
    branchEl.textContent = s.branch || "(no branch)";
    abEl.textContent = [s.ahead ? `↑${s.ahead}` : "", s.behind ? `↓${s.behind}` : ""].filter(Boolean).join(" ");
    const staged = s.files.filter(stagedHalf);
    const changed = s.files.filter((f) => workHalf(f) || f.index === "?");
    stagedList.replaceChildren(...staged.map((f) => row(f, true)));
    changesList.replaceChildren(...changed.map((f) => row(f, false)));
    stagedCount.textContent = staged.length ? ` ${staged.length}` : "";
    changesCount.textContent = changed.length ? ` ${changed.length}` : "";
    cleanNote.hidden = staged.length + changed.length > 0;
    commitBtn.disabled = !staged.length || !commitMsg.value.trim();
    // Selection follows the file: staging/unstaging moves it between lists (flip the
    // side we diff), committing removes it entirely (clear the pane).
    if (selected) {
      const inStaged = staged.some((f) => f.path === selected!.path);
      const inChanged = changed.some((f) => f.path === selected!.path);
      if (!inStaged && !inChanged) {
        selected = undefined;
        renderDiffEmpty();
      } else {
        if (selected.staged && !inStaged) selected.staged = false;
        else if (!selected.staged && !inChanged) selected.staged = true;
        void showDiff(selected.path, selected.staged, true);
      }
    }
  } catch (e) {
    showError((e as Error).message);
  }
}

// --- diff -----------------------------------------------------------------------

function renderDiffEmpty(): void {
  diffHead.hidden = true;
  diffEl.replaceChildren();
  diffEmpty.hidden = false;
}

function renderDiff(text: string): void {
  firstHunkLine = undefined;
  const frag = document.createDocumentFragment();
  for (const line of text.split("\n")) {
    const el = document.createElement("span");
    el.className = "ln";
    if (line.startsWith("@@")) {
      el.classList.add("hunk");
      if (firstHunkLine === undefined) firstHunkLine = Number(/\+(\d+)/.exec(line)?.[1]) || undefined;
    } else if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ") || line.startsWith("new file") || line.startsWith("deleted file") || line.startsWith("rename ") || line.startsWith("similarity ")) el.classList.add("meta");
    else if (line.startsWith("+")) el.classList.add("add");
    else if (line.startsWith("-")) el.classList.add("del");
    el.textContent = line || " ";
    frag.append(el);
  }
  diffEl.replaceChildren(frag);
}

async function showDiff(path: string, staged: boolean, silent = false): Promise<void> {
  const was = selected;
  selected = { path, staged };
  if (!silent || !was || was.path !== path) {
    for (const r of document.querySelectorAll(".row.active")) r.classList.remove("active");
  }
  try {
    const out = await api<{ diff: string }>(`diff?path=${encodeURIComponent(path)}&staged=${staged ? "1" : "0"}`);
    diffEmpty.hidden = true;
    diffHead.hidden = false;
    diffFile.textContent = `${path}${staged ? "  (staged)" : ""}`;
    renderDiff(out.diff || "(no changes)");
    if (!silent) void refresh(true); // re-render lists so the active row highlights
  } catch (e) {
    showError((e as Error).message);
  }
}

$("open-in-editor").onclick = () => {
  if (!selected) return;
  // Workspace-relative path = repo dir + repo-relative path; the SPA routes this into
  // a mounted code view (or opens one) — PLAN V1's direct-link contract.
  const file = repo ? `${repo}/${selected.path}` : selected.path;
  parent.postMessage({ type: "isolation:open-file", file, ...(firstHunkLine ? { line: firstHunkLine } : {}) }, "*");
};

// --- ops ------------------------------------------------------------------------

async function op(kind: "stage" | "unstage" | "discard", path: string): Promise<void> {
  try {
    await api(kind, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path }) });
    await refresh(true);
  } catch (e) {
    showError((e as Error).message);
  }
}

commitMsg.addEventListener("input", () => {
  commitBtn.disabled = !commitMsg.value.trim() || !stagedList.childElementCount;
});
commitBtn.onclick = async () => {
  const message = commitMsg.value.trim();
  if (!message) return;
  commitBtn.disabled = true;
  try {
    await api("commit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }) });
    commitMsg.value = "";
    clearError();
    await refresh(true);
  } catch (e) {
    showError((e as Error).message);
    commitBtn.disabled = false;
  }
};

$("refresh").onclick = () => void refresh(true);

// --- boot -----------------------------------------------------------------------

// Strip the bootstrap token (promoted to a cookie by the doorman).
const u = new URL(location.href);
if (u.searchParams.has("token")) {
  u.searchParams.delete("token");
  history.replaceState(null, "", u);
}

void loadRepos()
  .then(() => refresh(true))
  .catch((e) => showError((e as Error).message));
setInterval(() => {
  if (!document.hidden) void refresh();
}, 3500);
