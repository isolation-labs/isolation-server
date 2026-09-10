// THE AGENT VIEW, IN A TERMINAL — what `ssh <routeId>@<host>` lands you in.
//
// The agent view is an ACP conversation whose bridge fans out to N clients. `-s … acp` hands you the
// raw protocol, which is right for Zed and unreadable by a person. This is the client for the rest of
// us: the same conversation, live, both ways, with nothing to install — ssh and a key, exactly like
// opening a terminal view.
//
// IT IS THE CHANNEL'S PROCESS, not a program inside a shell. The bastion `exec`s this as the ssh
// channel itself (the way a terminal route execs `tmux attach`), so quitting it closes the channel
// and ends the connection. There is no shell behind it to fall back into — which is the point: an
// agent route is one door, and a shell there would be a way into the sandbox that refusing its
// subsystem and its exec was meant to prevent.
//
// IT SPAWNS THE ATTACH SCRIPT rather than opening its own socket. The WebSocket client, the
// handshake, the framing and the "does this bridge really serve MY view" check all live in
// `iso-acp-attach.mjs`; a second copy here would be a second place for a protocol bug to hide, and
// the two would drift. So this file is only a renderer, and its first job is proving that door works.
import { spawn } from "node:child_process";
import readline from "node:readline";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PORT = process.argv[2];
const VIEW_ID = process.argv[3];
const NAME = process.argv[4] || "agent";
const ATTACH = join(dirname(fileURLToPath(import.meta.url)), "iso-acp-attach.mjs");

if (!PORT) {
  process.stderr.write("usage: iso-acp-chat.mjs <port> <viewId> [name]\n");
  process.exit(2);
}

// ── Colour, but only when somebody is watching ─────────────────────────────────────────────────
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (n) => (s) => (tty ? `\x1b[${n}m${s}\x1b[0m` : s);
const dim = c("2");
const bold = c("1");
const cyan = c("36");
const green = c("32");
const yellow = c("33");
const red = c("31");

const child = spawn(process.execPath, [ATTACH, PORT, VIEW_ID ?? ""], { stdio: ["pipe", "pipe", "inherit"] });
const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);

// ── A transcript, not a canvas ─────────────────────────────────────────────────────────────────
// The browser view groups chunks into bubbles; a terminal is a stream, so the only grouping that
// matters is knowing when the SPEAKER changed — otherwise a turn's prose and its tool calls run
// together into one wall of text.
let speaker = "";
let atLineStart = true;

function say(who, label, text) {
  if (!text) return;
  if (speaker !== who) {
    if (!atLineStart) process.stdout.write("\n");
    process.stdout.write(`\n${label}\n`);
    speaker = who;
    atLineStart = true;
  }
  process.stdout.write(text);
  atLineStart = text.endsWith("\n");
}

function line(text) {
  if (!atLineStart) process.stdout.write("\n");
  process.stdout.write(`${text}\n`);
  atLineStart = true;
  speaker = "";
}

const textOf = (content) => {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map(textOf).join("");
  if (content && typeof content === "object") return typeof content.text === "string" ? content.text : "";
  return "";
};

// ── State ──────────────────────────────────────────────────────────────────────────────────────
let sessionId = "";
let nextId = 1;
let busy = false;
// A permission request is a QUESTION THE AGENT IS BLOCKED ON, so it takes over the prompt: anything
// else typed would go to a turn that is not running.
let pending;

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function prompt() {
  if (!atLineStart) {
    process.stdout.write("\n");
    atLineStart = true;
  }
  rl.setPrompt(pending ? yellow(`allow? [${pending.options.map((o, i) => `${i + 1}=${o.name}`).join(" ")}] `) : busy ? dim("… ") : cyan("> "));
  rl.prompt();
}

function render(u) {
  const k = u?.sessionUpdate;
  switch (k) {
    case "agent_message_chunk":
      return say("agent", green(bold(NAME)), textOf(u.content));
    case "agent_thought_chunk":
      return say("thought", dim("thinking"), dim(textOf(u.content)));
    case "user_message_chunk":
      // Somebody else is driving — the browser, Slack, another client. Showing it is the point: one
      // conversation, several windows on it.
      return say("user", dim("someone"), dim(textOf(u.content)));
    case "tool_call":
      return line(dim(`  · ${u.title ?? u.kind ?? "tool"}`));
    case "tool_call_update":
      if (u.status === "failed") line(red(`  · ${u.title ?? "tool"} failed`));
      return;
    default:
      return;
  }
}

// ── The stream ─────────────────────────────────────────────────────────────────────────────────
let acc = "";
child.stdout.on("data", (d) => {
  acc += d.toString("utf8");
  for (;;) {
    const nl = acc.indexOf("\n");
    if (nl === -1) break;
    const raw = acc.slice(0, nl).trim();
    acc = acc.slice(nl + 1);
    if (!raw) continue;
    let m;
    try {
      m = JSON.parse(raw);
    } catch {
      continue;
    }
    handle(m);
  }
});

function handle(m) {
  if (m.method === "session/request_permission" && m.id !== undefined) {
    pending = { id: m.id, options: (m.params?.options ?? []).map((o) => ({ optionId: o.optionId, name: o.name ?? o.optionId })) };
    line(yellow(`⚠ ${m.params?.toolCall?.title ?? "the agent is asking permission"}`));
    return prompt();
  }
  if (m.method === "session/update") return render(m.params?.update ?? m.params);
  if (m.method === "_iso/hello") {
    sessionId = m.params?.sessionId ?? "";
    const updates = m.params?.updates ?? [];
    line(dim(`— ${NAME}${updates.length ? `, ${updates.length} earlier update${updates.length === 1 ? "" : "s"} replayed` : ""} — /exit to leave, /cancel to interrupt —`));
    for (const u of updates) render(u?.update ?? u);
    return prompt();
  }
  if (m.method === "_iso/session") {
    sessionId = m.params?.sessionId ?? sessionId;
    return;
  }
  if (m.method === "_iso/turn") {
    const was = busy;
    busy = !!m.params?.active;
    if (was && !busy) prompt();
    return;
  }
  if (m.method === "_iso/status" && m.params?.error) return line(red(`  ! ${m.params.error}`));
  if (m.method === "_iso/permission_done") {
    // Another window answered first; the bridge ignores late answers, so drop ours rather than
    // leaving a prompt nobody can satisfy.
    if (pending) {
      pending = undefined;
      line(dim("  · answered in another window"));
      prompt();
    }
    return;
  }
  if (m.id !== undefined && m.method === undefined && m.error) return line(red(`  ! ${m.error.message ?? "refused"}`));
}

// ── Leaving ────────────────────────────────────────────────────────────────────────────────────
// QUITTING ENDS THE CONNECTION, because this process IS the ssh channel. Nothing to fall back to.
const leave = (code = 0) => {
  try {
    child.kill();
  } catch {
    /* already gone */
  }
  rl.close();
  process.exit(code);
};

child.on("exit", () => {
  line(dim("— the conversation closed —"));
  leave(0);
});

rl.on("line", (raw) => {
  const text = raw.trim();
  if (pending) {
    const n = Number(text);
    const pick = pending.options[n - 1] ?? pending.options.find((o) => o.optionId === text || o.name.toLowerCase() === text.toLowerCase());
    if (!pick) {
      line(dim("  · pick one of the numbers"));
      return prompt();
    }
    send({ jsonrpc: "2.0", id: pending.id, result: { outcome: { outcome: "selected", optionId: pick.optionId } } });
    pending = undefined;
    return prompt();
  }
  if (!text) return prompt();
  if (text === "/exit" || text === "/quit") return leave(0);
  if (text === "/cancel") {
    send({ jsonrpc: "2.0", id: nextId++, method: "session/cancel", params: { sessionId } });
    return prompt();
  }
  // ONE TURN AT A TIME is the bridge's rule, not ours — a second prompt while one runs is refused,
  // so say so rather than sending something that comes back as an error.
  if (busy) {
    line(dim("  · still working — /cancel to interrupt"));
    return prompt();
  }
  send({ jsonrpc: "2.0", id: nextId++, method: "session/prompt", params: { sessionId, prompt: [{ type: "text", text }] } });
  busy = true;
  prompt();
});

rl.on("SIGINT", () => {
  if (busy) {
    send({ jsonrpc: "2.0", id: nextId++, method: "session/cancel", params: { sessionId } });
    line(dim("  · cancelling…"));
    return prompt();
  }
  leave(0);
});
rl.on("close", () => leave(0));
