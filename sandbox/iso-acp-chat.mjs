// THE AGENT VIEW, IN A TERMINAL — what `ssh <routeId>@<host>` lands you in.
//
// The agent view is an ACP conversation whose bridge fans out to N clients — the page is one, and so
// is this. It is the ONE door on an agent route: the same conversation, live, both ways, rendered
// for a person, with nothing to install — ssh and a key, exactly like opening a terminal view.
//
// IT IS THE CHANNEL'S PROCESS, not a program inside a shell. The bastion `exec`s this as the ssh
// channel itself (the way a terminal route execs `tmux attach`), so quitting it closes the channel
// and ends the connection. There is no shell behind it to fall back into — which is the point: an
// agent route is one door, and a shell there would be a way into the sandbox that forcing this
// command — whatever the client asks to run — was meant to prevent.
//
// IT SPAWNS THE ATTACH SCRIPT rather than opening its own socket. The WebSocket client, the
// handshake, the framing and the "does this bridge really serve MY view" check all live in
// `iso-acp-attach.mjs`; a second copy here would be a second place for a protocol bug to hide, and
// the two would drift. So this file is only a renderer, and its first job is proving that door works.
import { spawn } from "node:child_process";
import readline from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PORT = process.argv[2];
const VIEW_ID = process.argv[3];
const NAME = process.argv[4] || "agent";
// THE LEADING DOT IS PART OF THE NAME. `acpview.ts` writes both scripts into the sandbox's /tmp as
// DOTFILES (`ATTACH_PATH` = `/tmp/.iso-acp-attach.mjs`, `CHAT_PATH` = `/tmp/.iso-acp-chat.mjs`), so
// a sibling resolved without it names a file that is never there — and the whole door then dies at
// spawn with a module-not-found, which reads as "the conversation closed" and nothing else.
const ATTACH = join(dirname(fileURLToPath(import.meta.url)), ".iso-acp-attach.mjs");

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
// A pipe whose far end is gone raises `error` (EPIPE) on the stream, and an unhandled one is an
// uncaught exception — a stack trace where a closing conversation belongs. The child's own exit is
// what ends this process; a failed write is only the same news arriving a moment earlier.
child.stdin.on("error", () => {});
// `spawn` reports "could not start at all" as `error`, never as `exit`, and unhandled it is again a
// stack trace. This is the case a broken attach path lands in, so it must say what happened.
child.on("error", (e) => {
  process.stderr.write(`the agent view could not be opened: ${e.message}\n`);
  process.exit(1);
});
const send = (msg) => {
  if (!child.stdin.destroyed) child.stdin.write(`${JSON.stringify(msg)}\n`);
};

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

// A NAME THAT CANNOT DRIVE THE TERMINAL: escapes and every other control character stripped, so a
// label somebody else chose is printed as the text it claims to be. (C1 too: an 8-bit CSI is one
// byte, and a terminal in that mode obeys it.)
const plain = (s) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();

// …AND THE SAME FOR EVERY BODY OF TEXT THIS PRINTS, which is the far bigger surface: a connector
// posts whole messages (a Slack line anyone in the channel can write), and the AGENT'S OWN PROSE
// quotes back whatever it just read — a file, a tool's output, a fetched page. All of it is written
// straight to a terminal, where an escape is an instruction and not text: clear the screen, move the
// cursor, set the window title, write the clipboard, redraw the transcript as if the agent had said
// something else. Only the two control characters prose actually uses survive: newline and tab. CR
// goes with the rest, because a bare one rewrites the line already printed.
const plainText = (s) => s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");

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
// The id of the prompt we are waiting on, so its answer can be told from any other response.
let promptId;
// WHAT WE JUST SENT, so the bridge's echo of it is not printed underneath what you typed.
//
// Every window renders a prompt from the bridge's echo — one source of truth, the sender included
// (iso-acp-bridge.mjs). In a browser that is right: the page has not drawn it yet. In a TERMINAL it
// is already on screen, because you typed it at the prompt, so the echo prints it a second time.
// And the `from` the bridge sends is "view" for EVERY window, so it cannot tell mine from anybody
// else's; the text I sent can.
let mine = [];
// The text of the prompt in flight, so a REFUSED one can take its note back (below).
let promptText;
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

function render(u, from) {
  const k = u?.sessionUpdate;
  switch (k) {
    case "agent_message_chunk":
      return say("agent", green(bold(NAME)), plainText(textOf(u.content)));
    case "agent_thought_chunk":
      return say("thought", dim("thinking"), dim(plainText(textOf(u.content))));
    case "user_message_chunk": {
      const text = textOf(u.content);
      // MY OWN ECHO: already on screen, above the prompt I typed it at.
      const i = mine.indexOf(text);
      if (i >= 0) {
        mine.splice(i, 1);
        return;
      }
      // SOMEBODY ELSE IS DRIVING — the browser, Slack, another terminal. Showing it is the point:
      // one conversation with several windows on it, and a turn you did not start is the thing you
      // most need to see. `from` names the door where the bridge knows one; "another window" is the
      // honest answer for a second browser tab or terminal, which it reports only as "view".
      //
      // IT IS A NAME A STRANGER CHOSE — a connector posts its own `from` (iso-acp-bridge.mjs bounds
      // the length and nothing else) — and it is written to a TERMINAL, where an escape sequence is
      // not text but an instruction: move the cursor, clear the screen, redraw a line as if the
      // agent had said it. So the control characters come out before it is printed, the same way
      // the shell's metacharacters come out of the label the route carries.
      const who = !from || from === "view" ? "another window" : plain(String(from)).slice(0, 40) || "another window";
      // The SENDER is part of the speaker, not just the label: two windows talking in turn are two
      // blocks, or the second one's prose runs on under the first one's name.
      return say(`user:${who}`, dim(who), dim(plainText(text)));
    }
    // A TOOL'S TITLE IS A ONE-LINE LABEL and it is the agent's text: a path it was asked to read, a
    // command somebody wrote. `plain`, not `plainText` — a newline in it would break the line it is
    // printed on, and there is no prose here that needs one.
    case "tool_call":
      return line(dim(`  · ${plain(String(u.title ?? u.kind ?? "tool"))}`));
    case "tool_call_update":
      if (u.status === "failed") line(red(`  · ${plain(String(u.title ?? "tool"))} failed`));
      return;
    default:
      return;
  }
}

// ── The stream ─────────────────────────────────────────────────────────────────────────────────
// A CHUNK BOUNDARY IS NOT A CHARACTER BOUNDARY: the attach script's stdout arrives in pipe-sized
// pieces, and an agent's prose is full of things outside ASCII (an em-dash, an accent, an emoji).
// `Buffer.toString("utf8")` turns each half of a split sequence into U+FFFD, so the transcript
// quietly stops being what the agent said. The decoder holds the partial sequence instead.
const outDecoder = new StringDecoder("utf8");
let acc = "";
child.stdout.on("data", (d) => {
  acc += outDecoder.write(d);
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
    // AN OPTION NAME IS AGENT TEXT TOO, and it goes somewhere worse than the transcript: into the
    // PROMPT LINE itself. An escape there redraws the question a person is about to answer — "allow?
    // [1=reject 2=allow]" repainted the other way round is a yes taken for a no. Same treatment as
    // the title, one line each. `optionId` is never printed, only compared.
    pending = { id: m.id, options: (m.params?.options ?? []).map((o, i) => ({ optionId: o.optionId, name: plain(String(o.name ?? o.optionId ?? "")) || `option ${i + 1}` })) };
    line(yellow(`⚠ ${plain(String(m.params?.toolCall?.title ?? "the agent is asking permission"))}`));
    return prompt();
  }
  if (m.method === "session/update") return render(m.params?.update ?? m.params, m.params?._meta?.iso?.from);
  if (m.method === "_iso/hello") {
    sessionId = m.params?.sessionId ?? "";
    // THE REPLAY BUFFER HOLDS WHOLE NOTIFICATIONS, not bare updates: the bridge pushes the
    // `session/update` MESSAGE it received, so what renders is `params.update` — the same reach the
    // browser store makes. Taking the outer object for an update finds no `sessionUpdate`, falls to
    // the default case, and replays an empty transcript under a line announcing how much it replayed.
    const updates = (m.params?.updates ?? []).filter((u) => u?.method === "session/update");
    line(dim(`— ${NAME}${updates.length ? `, ${updates.length} earlier update${updates.length === 1 ? "" : "s"} replayed` : ""} — /exit to leave, /cancel to interrupt —`));
    for (const u of updates) render(u.params?.update, u.params?._meta?.iso?.from);
    // A TURN MAY ALREADY BE RUNNING when we join — somebody else's prompt, from another window. The
    // hello says so, and without reading it the first thing typed here goes into a refusal.
    busy = !!m.params?.turn?.active;
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
  if (m.method === "_iso/status" && m.params?.error) return line(red(`  ! ${plain(String(m.params.error))}`));
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
  if (m.id !== undefined && m.method === undefined) {
    if (m.error) line(red(`  ! ${plain(String(m.error.message ?? "refused"))}`));
    // THE BRIDGE ANSWERS A PROMPT WHEN ITS TURN ENDS — and also when the turn never started (the
    // agent would not spawn, a turn was already running). In that second case no `_iso/turn` ever
    // follows, so without clearing it here the client sits at "…" forever, refusing everything
    // typed with "still working" while there is nothing to cancel.
    if (m.id === promptId) {
      promptId = undefined;
      // A REFUSED PROMPT NEVER ECHOES — the bridge echoes only once the turn is really running — so
      // its note has to come back off the list. Left there it would silently swallow the next
      // identical line somebody types in another window.
      if (m.error && promptText !== undefined) {
        const at = mine.indexOf(promptText);
        if (at >= 0) mine.splice(at, 1);
      }
      promptText = undefined;
      if (busy) {
        busy = false;
        prompt();
      }
    }
    return;
  }
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
  promptId = nextId++;
  // THE ECHO IS COMING: the bridge renders every prompt to every window from its own echo, this one
  // included, so leave a note of what was sent — `render` drops the matching echo instead of
  // printing the line a second time under the one you typed.
  promptText = text;
  mine.push(text);
  send({ jsonrpc: "2.0", id: promptId, method: "session/prompt", params: { sessionId, prompt: [{ type: "text", text }] } });
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
