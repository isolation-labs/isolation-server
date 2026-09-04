// The agent view (PLAN §5d): a real ACP client, rendered with Preact over the zustand store.
// The harness supplies everything that used to be faked — slash commands, modes, models,
// tool calls, permissions — and this page only renders it.
import { render, type ComponentChildren } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import type { AvailableCommand, PlanEntry, SessionConfigOption, ToolCallContent } from "@agentclientprotocol/sdk";
import "./agent.css";
import { connect, type Connection } from "./acp.js";
import { renderMarkdown } from "./markdown.js";
import { answerPermission, setPending, store, type Item, type State, type ToolCallState } from "./store.js";

// --- store hook ------------------------------------------------------------------

function useAppState(): State {
  const [s, setS] = useState(store.getState());
  useEffect(() => store.subscribe(setS), []);
  return s;
}

// --- helpers ----------------------------------------------------------------------

const phaseLabel: Record<State["phase"], string> = {
  connecting: "connecting…",
  idle: "waking the agent…",
  starting: "starting the agent…",
  ready: "ready",
  stopped: "stopped",
  error: "error",
};

const TOOL_ICON: Record<string, string> = { read: "◎", edit: "✎", delete: "✕", move: "⇄", search: "⌕", execute: "▶", think: "◌", fetch: "⇣", switch_mode: "⇆", other: "⚙" };

// A workspace-relative file (+ line) → the code view. The page is an iframe inside the SPA,
// which routes `isolation:open-file` into the session's code view (or opens one); standalone
// there is nothing to open, so the click is a no-op beyond the hint.
export function openInEditor(file: string, line?: number): void {
  const rel = file.replace(/^\/workspace\//, "").replace(/^\.\//, "");
  if (window.parent !== window) window.parent.postMessage({ type: "isolation:open-file", file: rel, ...(line ? { line } : {}) }, "*");
  else showError("Open this chat inside a session to jump to files");
}

function Markdown({ text, className }: { text: string; className?: string }) {
  const html = useMemo(() => renderMarkdown(text), [text]);
  const onClick = (e: MouseEvent) => {
    const a = (e.target as HTMLElement).closest?.("a.file-link") as HTMLAnchorElement | null;
    if (!a) return;
    e.preventDefault();
    openInEditor(a.dataset.file ?? "", a.dataset.line ? Number(a.dataset.line) : undefined);
  };
  return <div class={`md ${className ?? ""}`} onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />;
}

// A small line diff (LCS on lines) for edit tool calls; big files fall back to after-only.
function lineDiff(oldText: string, newText: string): { t: " " | "-" | "+"; s: string }[] | undefined {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  if (a.length > 400 || b.length > 400) return undefined;
  const n = a.length;
  const m = b.length;
  const dp: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: { t: " " | "-" | "+"; s: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ t: " ", s: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ t: "-", s: a[i++] });
    else out.push({ t: "+", s: b[j++] });
  }
  while (i < n) out.push({ t: "-", s: a[i++] });
  while (j < m) out.push({ t: "+", s: b[j++] });
  // Collapse long unchanged runs to keep the card short.
  const compact: typeof out = [];
  let run: typeof out = [];
  const flushRun = (edge: boolean) => {
    if (run.length > 6) {
      if (!edge) compact.push(...run.slice(0, 3));
      compact.push({ t: " ", s: `… ${run.length - (edge ? 3 : 6)} unchanged lines …` });
      compact.push(...run.slice(-3));
    } else compact.push(...run);
    run = [];
  };
  for (const l of out) {
    if (l.t === " ") run.push(l);
    else {
      flushRun(compact.length === 0);
      compact.push(l);
    }
  }
  flushRun(true);
  return compact;
}

function DiffView({ path, oldText, newText }: { path: string; oldText?: string | null; newText: string }) {
  const diff = useMemo(() => (oldText != null ? lineDiff(oldText, newText) : undefined), [oldText, newText]);
  return (
    <div class="diff">
      <div class="diff-path file-link" title="Open in the code view" onClick={() => openInEditor(path)}>
        {path.replace(/^\/workspace\//, "")}
      </div>
      {diff ? (
        <pre class="diff-body">
          {diff.map((l, k) => (
            <div key={k} class={`dl ${l.t === "+" ? "add" : l.t === "-" ? "del" : "ctx"}`}>
              <span class="sign">{l.t}</span>
              {l.s}
            </div>
          ))}
        </pre>
      ) : (
        <pre class="diff-body">{clip(newText, 6000)}</pre>
      )}
    </div>
  );
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n)}\n… (${s.length - n} more chars)` : s);

function ToolContent({ c }: { c: ToolCallContent }) {
  if (c.type === "diff") return <DiffView path={c.path} oldText={c.oldText} newText={c.newText} />;
  if (c.type === "terminal") return <div class="tool-text">terminal {c.terminalId}</div>;
  const b = c.content;
  if (b.type === "text") return /^\s*```/.test(b.text) || /\n\s*[-*] |\n#{1,3} /.test(b.text) ? <Markdown className="tool-md" text={clip(b.text, 8000)} /> : <pre class="tool-text">{clip(b.text, 6000)}</pre>;
  return <div class="tool-text">[{b.type}]</div>;
}

function ToolCard({ call }: { call: ToolCallState }) {
  const [open, setOpen] = useState(false);
  const status = call.status ?? "pending";
  const hasBody = call.content.length > 0 || call.rawInput !== undefined || call.rawOutput !== undefined;
  return (
    <div class={`tool ${status}`}>
      <button class="tool-head" onClick={() => setOpen(!open)} disabled={!hasBody}>
        <span class="tool-icon">{TOOL_ICON[call.kind ?? "other"] ?? "⚙"}</span>
        <span class="tool-title">{call.title}</span>
        {call.locations.length > 0 && (
          <span class="tool-locs">
            {call.locations.slice(0, 3).map((l, k) => (
              <span
                key={k}
                class="loc file-link"
                title="Open in the code view"
                onClick={(e) => {
                  e.stopPropagation();
                  openInEditor(l.path, l.line ?? undefined);
                }}
              >
                {l.path.replace(/^\/workspace\//, "")}
                {l.line ? `:${l.line}` : ""}
              </span>
            ))}
          </span>
        )}
        <span class={`tool-status ${status}`}>{status === "in_progress" ? <span class="spin" /> : status === "completed" ? "✓" : status === "failed" ? "✕" : "…"}</span>
        {hasBody && <span class="tool-caret">{open ? "▾" : "▸"}</span>}
      </button>
      {open && hasBody && (
        <div class="tool-body">
          {call.content.map((c, k) => (
            <ToolContent key={k} c={c} />
          ))}
          {call.content.length === 0 && call.rawInput !== undefined && <pre class="tool-text">{clip(JSON.stringify(call.rawInput, null, 2), 4000)}</pre>}
          {call.content.length === 0 && call.rawOutput !== undefined && <pre class="tool-text">{clip(typeof call.rawOutput === "string" ? call.rawOutput : JSON.stringify(call.rawOutput, null, 2), 4000)}</pre>}
        </div>
      )}
    </div>
  );
}

function ItemView({ item, agentName }: { item: Item; agentName: string }) {
  switch (item.kind) {
    case "user":
      return (
        <div class="msg user">
          <div class="bubble">
            {item.from && item.from !== "view" && <div class="from">via {item.from}</div>}
            <div class="pre">{item.text}</div>
          </div>
        </div>
      );
    case "agent":
      return (
        <div class="msg assistant">
          {item.thought && (
            <details class="thought">
              <summary>Thinking</summary>
              <Markdown text={item.thought} />
            </details>
          )}
          {item.text && (
            <div class="bubble">
              <div class="who">{agentName}</div>
              <Markdown text={item.text} />
            </div>
          )}
        </div>
      );
    case "tool":
      return <ToolCard call={item.call} />;
    case "note":
      return <div class="note">{item.text}</div>;
  }
}

function PlanView({ plan }: { plan: PlanEntry[] }) {
  const [open, setOpen] = useState(true);
  const done = plan.filter((e) => e.status === "completed").length;
  return (
    <div class="plan">
      <button class="plan-head" onClick={() => setOpen(!open)}>
        <span>Plan</span>
        <span class="plan-count">
          {done}/{plan.length}
        </span>
        <span class="tool-caret">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <ul>
          {plan.map((e, k) => (
            <li key={k} class={`pe ${e.status} ${e.priority}`}>
              <span class="pe-mark">{e.status === "completed" ? "✓" : e.status === "in_progress" ? "•" : "○"}</span>
              {e.content}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Permissions({ s }: { s: State }) {
  if (!s.permissions.length) return null;
  const p = s.permissions[0];
  const tc = p.request.toolCall;
  return (
    <div class="perm">
      <div class="perm-title">
        <span class="tool-icon">{TOOL_ICON[tc.kind ?? "other"] ?? "⚙"}</span>
        {tc.title ?? "Permission requested"}
      </div>
      {tc.content?.map((c, k) => (
        <ToolContent key={k} c={c} />
      ))}
      {!tc.content?.length && tc.rawInput !== undefined && <pre class="tool-text">{clip(JSON.stringify(tc.rawInput, null, 2), 2000)}</pre>}
      <div class="perm-opts">
        {p.request.options.map((o) => (
          <button key={o.optionId} class={`opt ${o.kind}`} onClick={() => answerPermission(p.id, o.optionId)}>
            {o.name}
          </button>
        ))}
      </div>
    </div>
  );
}

// --- header: identity, status, modes and config options ------------------------------

function Header({ s, conn }: { s: State; conn: Connection }) {
  const modes = s.modes;
  const options = (s.configOptions ?? []).filter((o) => o.category !== "mode" && o.id !== "mode");
  const meta = s.agent ? `${s.agent.harness}${s.agent.model ? ` · ${s.agent.model}` : ""}` : "";
  return (
    <header id="head">
      <span class={`dot ${s.phase} ${s.connected ? "" : "offline"}`} title={s.connected ? phaseLabel[s.phase] : "disconnected — reconnecting"} />
      <span id="agent-name">{s.agent?.name ?? "agent"}</span>
      <span id="agent-meta">{meta}</span>
      <span class="spacer" />
      {modes && modes.availableModes.length > 1 && (
        <label class="ctl" title={modes.availableModes.find((m) => m.id === modes.currentModeId)?.description ?? "mode"}>
          <select value={modes.currentModeId} onChange={(e) => conn.setMode((e.target as HTMLSelectElement).value).catch(showError)}>
            {modes.availableModes.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {options.map((o) => (
        <ConfigControl key={o.id} o={o} conn={conn} />
      ))}
      {(s.phase === "stopped" || s.phase === "error") && (
        <button class="btn" onClick={() => conn.restart().catch(showError)}>
          Restart
        </button>
      )}
    </header>
  );
}

function ConfigControl({ o, conn }: { o: SessionConfigOption; conn: Connection }) {
  if (o.type === "boolean") {
    return (
      <label class="ctl chk" title={o.description ?? o.name}>
        <input type="checkbox" checked={Boolean(o.currentValue)} onChange={(e) => conn.setConfig(o.id, (e.target as HTMLInputElement).checked).catch(showError)} />
        {o.name}
      </label>
    );
  }
  const opts = o.options as unknown as ({ value: string; name: string } | { name: string; options: { value: string; name: string }[] })[];
  return (
    <label class="ctl" title={o.description ?? o.name}>
      <select value={o.currentValue} onChange={(e) => conn.setConfig(o.id, (e.target as HTMLSelectElement).value).catch(showError)}>
        {opts.map((g, k) =>
          "options" in g ? (
            <optgroup key={k} label={g.name}>
              {g.options.map((x) => (
                <option key={x.value} value={x.value}>
                  {x.name}
                </option>
              ))}
            </optgroup>
          ) : (
            <option key={g.value} value={g.value}>
              {g.name}
            </option>
          ),
        )}
      </select>
    </label>
  );
}

// --- composer with slash-command completion --------------------------------------------

let errorTimer: number | undefined;
function showError(e: unknown): void {
  const bar = document.getElementById("error-bar");
  if (!bar) return;
  bar.textContent = String((e as Error)?.message ?? e);
  if (errorTimer) clearTimeout(errorTimer);
  errorTimer = window.setTimeout(() => (bar.textContent = ""), 8000);
}

function Composer({ s, conn }: { s: State; conn: Connection }) {
  const [text, setText] = useState("");
  const [sel, setSel] = useState(0);
  const ta = useRef<HTMLTextAreaElement>(null);
  const busy = s.turn.active;
  const canSend = s.phase === "ready" && s.connected && !!s.sessionId;
  const palette = useMemo(() => {
    const m = /^\/([\w:$.-]*)$/.exec(text);
    if (!m) return [] as AvailableCommand[];
    const q = m[1].toLowerCase();
    return s.commands.filter((c) => c.name.toLowerCase().startsWith(q)).slice(0, 12);
  }, [text, s.commands]);
  useEffect(() => setSel(0), [palette.length]);

  const grow = () => {
    const el = ta.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 180)}px`;
  };
  const accept = (c: AvailableCommand) => {
    setText(`/${c.name} `);
    requestAnimationFrame(() => ta.current?.focus());
  };
  const send = () => {
    const t = text.trim();
    if (!t || !canSend || busy) return;
    setText("");
    requestAnimationFrame(grow);
    setPending(t);
    conn.prompt(t).catch((e) => {
      setPending(undefined);
      showError(e);
    });
  };
  const onKey = (e: KeyboardEvent) => {
    if (palette.length) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSel((sel + 1) % palette.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSel((sel - 1 + palette.length) % palette.length);
        return;
      }
      if (e.key === "Tab" || (e.key === "Enter" && !e.shiftKey)) {
        e.preventDefault();
        accept(palette[sel]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setText(text + " ");
        return;
      }
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };
  return (
    <footer id="composer">
      {palette.length > 0 && (
        <div class="palette">
          {palette.map((c, k) => (
            <button key={c.name} class={`cmd ${k === sel ? "sel" : ""}`} onMouseEnter={() => setSel(k)} onClick={() => accept(c)}>
              <span class="cmd-name">/{c.name}</span>
              <span class="cmd-desc">{c.description}</span>
              {c.input?.hint && <span class="cmd-hint">{c.input.hint}</span>}
            </button>
          ))}
        </div>
      )}
      <div class="row">
        <textarea
          ref={ta}
          rows={1}
          value={text}
          placeholder={canSend ? (busy ? "The agent is working… (queue is one deep)" : `Message ${s.agent?.name ?? "the agent"} — / for commands`) : phaseLabel[s.phase]}
          onInput={(e) => {
            setText((e.target as HTMLTextAreaElement).value);
            grow();
          }}
          onKeyDown={onKey}
          disabled={!s.connected}
        />
        {busy ? (
          <button class="stop" title="Stop the turn" onClick={() => conn.cancel().catch(showError)}>
            ■
          </button>
        ) : (
          <button class="send" title="Send" onClick={send} disabled={!canSend || !text.trim()}>
            ↑
          </button>
        )}
      </div>
    </footer>
  );
}

// --- the app -------------------------------------------------------------------------

function Thread({ s, children }: { s: State; children?: ComponentChildren }) {
  const scroll = useRef<HTMLElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = scroll.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  });
  const onScroll = () => {
    const el = scroll.current;
    if (el) stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  };
  const name = s.agent?.name ?? "agent";
  return (
    <main id="scroll" ref={scroll} onScroll={onScroll}>
      {s.truncated && <div class="note">Earlier messages are not shown (long conversation).</div>}
      <div id="thread">
        {s.items.map((it) => (
          <ItemView key={it.id} item={it} agentName={name} />
        ))}
        {s.pendingPrompt && (
          <div class="msg user pending">
            <div class="bubble">
              <div class="pre">{s.pendingPrompt}</div>
            </div>
          </div>
        )}
        {s.turn.active && (
          <div class="msg assistant working">
            <div class="bubble">
              <span class="spin" /> {name} is working{s.turn.from && s.turn.from !== "view" ? ` (via ${s.turn.from})` : ""}…
            </div>
          </div>
        )}
      </div>
      {s.items.length === 0 && !s.pendingPrompt && (
        <div id="empty">
          <div class="empty-inner">
            <div class="empty-mark">◈</div>
            <div id="empty-line">{s.phase === "ready" ? `Send the first message to ${name}` : phaseLabel[s.phase]}</div>
            <div class="empty-hint">{s.error ? s.error : "This view is its own conversation with the agent. Type / to see the commands the harness offers."}</div>
          </div>
        </div>
      )}
      {children}
    </main>
  );
}

function App() {
  const s = useAppState();
  const conn = useMemo(() => connect(), []);
  useEffect(() => {
    if (s.agent) document.title = `${s.agent.name} — Isolation`;
  }, [s.agent?.name]);
  return (
    <div id="app">
      <Header s={s} conn={conn} />
      <Thread s={s} />
      {s.plan && s.plan.length > 0 && <PlanView plan={s.plan} />}
      <Permissions s={s} />
      {s.error && s.phase === "error" && <div class="status-bar error">{s.error}</div>}
      {!s.connected && s.phase !== "connecting" && <div class="status-bar">disconnected — reconnecting…</div>}
      <Composer s={s} conn={conn} />
      <div id="error-bar" />
    </div>
  );
}

// Strip the bootstrap token from the address bar (the doorman promoted it to a cookie).
const u = new URL(location.href);
if (u.searchParams.has("token")) {
  u.searchParams.delete("token");
  history.replaceState(null, "", u);
}

render(<App />, document.getElementById("root") as HTMLElement);
