// `isolation agent` — the agent view, in your terminal.
//
// The agent view is an ACP conversation, and its bridge already fans out to N clients: the browser
// page is one, `ssh -s <route>@<host> acp` is another. Both of those hand you the PROTOCOL — which is
// what a client consumes, and is unreadable by hand. This is the client.
//
// So: the same conversation the session screen is showing, in a terminal, both ways. What you type
// arrives there; what happens there arrives here — including while somebody else is driving from the
// browser, because neither of you is special.
//
// TWO WAYS IN, and the difference is only where the server is:
//   • THIS machine runs the server → the doorman's own `/v/<viewId>` WebSocket, authorized with the
//     master token this CLI already holds. No ssh, no bastion, no key.
//   • the server is somewhere else → `ssh -s <routeId>@<host> acp`, whose stdio is the same stream.
//     One renderer either way; only the transport differs.
//
// WHY A HAND-WRITTEN WEBSOCKET CLIENT AGAIN: this package has no `ws` dependency, and adding one for
// a CLI subcommand is a poor trade against ~70 lines. `sandbox/iso-acp-attach.mjs` cannot be shared
// with it — that file is written into a sandbox as a single standalone script and may import nothing.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import net from "node:net";
import readline from "node:readline";
import type { Duplex } from "node:stream";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ── Colour, but only when somebody is watching ─────────────────────────────────────────────────
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (n: string) => (s: string) => (tty ? `\x1b[${n}m${s}\x1b[0m` : s);
const dim = c("2");
const bold = c("1");
const cyan = c("36");
const green = c("32");
const yellow = c("33");
const red = c("31");

// ── A minimal RFC 6455 client ──────────────────────────────────────────────────────────────────

interface Wire {
  send(msg: unknown): void;
  close(): void;
  onMessage(fn: (msg: any) => void): void;
  onClose(fn: (why?: string) => void): void;
}

/** The doorman's `/v/<viewId>` upgrade, which is the same socket the browser page opens. */
function wsConnect(base: string, viewId: string, token: string): Promise<Wire> {
  const u = new URL(base);
  return new Promise((resolve, reject) => {
    const sock = net.connect(Number(u.port || 80), u.hostname);
    let handshaken = false;
    let buf = Buffer.alloc(0);
    let fragments: Buffer[] = [];
    let fragOp = 0;
    const key = randomBytes(16).toString("base64");
    const expect = createHash("sha1").update(key + GUID).digest("base64");
    let onMessage: (m: any) => void = () => {};
    let onClose: (w?: string) => void = () => {};

    const fail = (why: string) => {
      sock.destroy();
      reject(new Error(why));
    };

    sock.on("error", (e) => fail(e.message));
    sock.on("close", () => onClose());
    sock.on("connect", () => {
      sock.write(
        [
          `GET /v/${encodeURIComponent(viewId)} HTTP/1.1`,
          `Host: ${u.host}`,
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Key: ${key}`,
          "Sec-WebSocket-Version: 13",
          // The MASTER token, which `authorized()` accepts directly — this CLI is the server's own
          // operator, not a browser that has to be handed a scoped view token.
          `Authorization: Bearer ${token}`,
          "",
          "",
        ].join("\r\n"),
      );
    });

    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!handshaken) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = buf.subarray(0, end).toString("latin1");
        buf = buf.subarray(end + 4);
        if (!/^HTTP\/1\.1 101/i.test(head)) return fail(`the server refused the connection: ${head.split("\r\n")[0]}`);
        if (/sec-websocket-accept:\s*(\S+)/i.exec(head)?.[1] !== expect) return fail("the handshake did not verify");
        handshaken = true;
        resolve({
          send: (msg) => sendFrame(sock, 0x1, Buffer.from(JSON.stringify(msg), "utf8")),
          close: () => sock.destroy(),
          onMessage: (fn) => (onMessage = fn),
          onClose: (fn) => (onClose = fn),
        });
      }
      // Frames.
      for (;;) {
        if (buf.length < 2) return;
        const fin = (buf[0] & 0x80) !== 0;
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          const big = buf.readBigUInt64BE(2);
          if (big > BigInt(Number.MAX_SAFE_INTEGER)) return fail("frame too large");
          len = Number(big);
          off = 10;
        }
        let mask: Buffer | undefined;
        if (masked) {
          if (buf.length < off + 4) return;
          mask = buf.subarray(off, off + 4);
          off += 4;
        }
        if (buf.length < off + len) return;
        let payload = Buffer.from(buf.subarray(off, off + len));
        if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
        buf = buf.subarray(off + len);

        if (opcode === 0x8) return void onClose();
        if (opcode === 0x9) {
          sendFrame(sock, 0xa, payload);
          continue;
        }
        if (opcode === 0xa) continue;
        // A replay buffer is far past one frame, so continuation is the normal case, not an edge one.
        if (opcode === 0x0) {
          fragments.push(payload);
          if (!fin) continue;
          deliver(fragOp, Buffer.concat(fragments));
          fragments = [];
          continue;
        }
        if (!fin) {
          fragOp = opcode;
          fragments = [payload];
          continue;
        }
        deliver(opcode, payload);
      }
    });

    function deliver(opcode: number, payload: Buffer) {
      if (opcode !== 0x1) return;
      try {
        onMessage(JSON.parse(payload.toString("utf8")));
      } catch {
        /* a frame that is not JSON is not ours to render */
      }
    }
  });
}

/** A CLIENT MUST MASK every frame (RFC 6455 §5.3); a compliant server closes on an unmasked one. */
function sendFrame(sock: Duplex, opcode: number, payload: Buffer): void {
  const len = payload.length;
  const head = Buffer.alloc(len < 126 ? 6 : len < 65536 ? 8 : 14);
  head[0] = 0x80 | opcode;
  const mask = randomBytes(4);
  if (len < 126) {
    head[1] = 0x80 | len;
    mask.copy(head, 2);
  } else if (len < 65536) {
    head[1] = 0x80 | 126;
    head.writeUInt16BE(len, 2);
    mask.copy(head, 4);
  } else {
    head[1] = 0x80 | 127;
    head.writeBigUInt64BE(BigInt(len), 2);
    mask.copy(head, 10);
  }
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4];
  sock.write(Buffer.concat([head, body]));
}

/** The same stream, over a remote server's ssh door. One renderer, two transports. */
function sshWire(destination: string): Wire {
  // `-s` takes the subsystem in the COMMAND position — after the destination. The other order dials
  // a host literally called "acp".
  const child = spawn("ssh", ["-s", destination, "acp"], { stdio: ["pipe", "pipe", "inherit"] });
  let onMessage: (m: any) => void = () => {};
  let onClose: (w?: string) => void = () => {};
  let acc = "";
  child.stdout.on("data", (d: Buffer) => {
    acc += d.toString("utf8");
    for (;;) {
      const nl = acc.indexOf("\n");
      if (nl === -1) break;
      const line = acc.slice(0, nl).trim();
      acc = acc.slice(nl + 1);
      if (!line) continue;
      try {
        onMessage(JSON.parse(line));
      } catch {
        /* not ours */
      }
    }
  });
  child.on("exit", () => onClose());
  return {
    send: (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`),
    close: () => child.kill(),
    onMessage: (fn) => (onMessage = fn),
    onClose: (fn) => (onClose = fn),
  };
}

// ── Rendering ──────────────────────────────────────────────────────────────────────────────────

const textOf = (content: any): string => {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map(textOf).join("");
  if (content && typeof content === "object") return typeof content.text === "string" ? content.text : "";
  return "";
};

/**
 * A transcript, not a canvas. The browser view groups chunks into bubbles; a terminal is a stream, so
 * the only grouping that matters is knowing when the SPEAKER changed — otherwise a turn's text and
 * its tool calls run together into one wall.
 */
class Render {
  private speaker = "";
  private atLineStart = true;

  private prefix(who: string, label: string) {
    if (this.speaker === who) return;
    if (!this.atLineStart) process.stdout.write("\n");
    process.stdout.write(`\n${label}\n`);
    this.speaker = who;
    this.atLineStart = true;
  }

  text(who: string, label: string, s: string) {
    if (!s) return;
    this.prefix(who, label);
    process.stdout.write(s);
    this.atLineStart = s.endsWith("\n");
  }

  /** A one-line event — a tool call, a status. Never mid-sentence. */
  line(s: string) {
    if (!this.atLineStart) process.stdout.write("\n");
    process.stdout.write(`${s}\n`);
    this.atLineStart = true;
    this.speaker = "";
  }

  /** The prompt has to start on a clean line, or it lands inside the agent's last word. */
  ready() {
    if (!this.atLineStart) process.stdout.write("\n");
    this.atLineStart = true;
  }
}

export interface AgentCliOptions {
  /** A local view id, or a remote `<routeId>@<host>`. */
  target: { kind: "local"; base: string; token: string; viewId: string; label?: string } | { kind: "ssh"; destination: string };
}

export async function runAgentCli(opts: AgentCliOptions): Promise<number> {
  const wire = opts.target.kind === "ssh" ? sshWire(opts.target.destination) : await wsConnect(opts.target.base, opts.target.viewId, opts.target.token);
  const r = new Render();
  let sessionId = "";
  let nextId = 1;
  let busy = false;
  // A permission request is a QUESTION THE AGENT IS BLOCKED ON, so it takes over the prompt until
  // it is answered — anything else typed would go to a turn that is not running.
  let pending: { id: unknown; options: { optionId: string; name: string }[] } | undefined;
  const agentName = opts.target.kind === "local" ? opts.target.label || "agent" : "agent";

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: cyan("> ") });

  const prompt = () => {
    r.ready();
    if (pending) {
      rl.setPrompt(yellow(`allow? [${pending.options.map((o, i) => `${i + 1}=${o.name}`).join(" ")}] `));
    } else {
      rl.setPrompt(busy ? dim("… (ctrl-c to interrupt) ") : cyan("> "));
    }
    rl.prompt();
  };

  wire.onMessage((m: any) => {
    // A request FROM the agent: today only a permission ask.
    if (m.method === "session/request_permission" && m.id !== undefined) {
      const opts2 = (m.params?.options ?? []).map((o: any) => ({ optionId: o.optionId, name: o.name ?? o.optionId }));
      pending = { id: m.id, options: opts2 };
      r.line(yellow(`\n⚠ ${m.params?.toolCall?.title ?? "The agent is asking permission"}`));
      return prompt();
    }
    if (m.method === "session/update") {
      const u = m.params?.update ?? m.params;
      switch (u?.sessionUpdate) {
        case "agent_message_chunk":
          return r.text("agent", green(bold(agentName)), textOf(u.content));
        case "agent_thought_chunk":
          return r.text("thought", dim("thinking"), dim(textOf(u.content)));
        case "user_message_chunk":
          // Somebody else is driving — the browser, Slack, another client. Showing it is the point:
          // this is one conversation with several windows on it.
          return r.text("user", dim("someone"), dim(textOf(u.content)));
        case "tool_call":
          return r.line(dim(`  · ${u.title ?? u.kind ?? "tool"}`));
        case "tool_call_update":
          if (u.status === "failed") r.line(red(`  · ${u.title ?? "tool"} failed`));
          return;
        case "plan":
        case "plan_update":
          return;
        default:
          return;
      }
    }
    // The bridge's own notifications.
    if (m.method === "_iso/hello") {
      sessionId = m.params?.sessionId ?? "";
      const n = (m.params?.updates ?? []).length;
      r.line(dim(`— connected${n ? `, ${n} earlier update${n === 1 ? "" : "s"} replayed` : ""} —`));
      for (const u of m.params?.updates ?? []) wireUpdate(u);
      return prompt();
    }
    if (m.method === "_iso/session") {
      sessionId = m.params?.sessionId ?? sessionId;
      return;
    }
    if (m.method === "_iso/turn") {
      const wasBusy = busy;
      busy = !!m.params?.active;
      if (wasBusy && !busy) prompt();
      return;
    }
    if (m.method === "_iso/status" && m.params?.error) return r.line(red(`  ! ${m.params.error}`));
    if (m.method === "_iso/permission_done") {
      // Another window answered first. The bridge ignores late answers, so drop ours rather than
      // leaving a prompt nobody can satisfy.
      if (pending) {
        pending = undefined;
        r.line(dim("  · answered in another window"));
        prompt();
      }
      return;
    }
    // A response to something we sent.
    if (m.id !== undefined && m.method === undefined) {
      if (m.error) r.line(red(`  ! ${m.error.message ?? "the agent refused that"}`));
      return;
    }
  });

  /** Replayed updates arrive inside `_iso/hello`, in the same shape as a live notification. */
  function wireUpdate(u: any) {
    const k = u?.sessionUpdate ?? u?.update?.sessionUpdate;
    const uu = u?.update ?? u;
    if (k === "agent_message_chunk") r.text("agent", green(bold(agentName)), textOf(uu.content));
    else if (k === "user_message_chunk") r.text("user", dim("someone"), dim(textOf(uu.content)));
  }

  wire.onClose(() => {
    r.line(dim("— the conversation closed —"));
    rl.close();
    process.exit(0);
  });

  rl.on("line", (raw) => {
    const line = raw.trim();
    if (pending) {
      const n = Number(line);
      const pick = pending.options[n - 1] ?? pending.options.find((o) => o.optionId === line || o.name.toLowerCase() === line.toLowerCase());
      if (!pick) {
        r.line(dim("  · pick one of the numbers"));
        return prompt();
      }
      wire.send({ jsonrpc: "2.0", id: pending.id, result: { outcome: { outcome: "selected", optionId: pick.optionId } } });
      pending = undefined;
      return prompt();
    }
    if (!line) return prompt();
    if (line === "/exit" || line === "/quit") {
      wire.close();
      rl.close();
      return process.exit(0);
    }
    if (line === "/cancel") {
      wire.send({ jsonrpc: "2.0", id: nextId++, method: "session/cancel", params: { sessionId } });
      return prompt();
    }
    // ONE TURN AT A TIME is the bridge's rule, not ours — a second prompt while one runs is refused,
    // so say it here rather than sending something that comes back as an error.
    if (busy) {
      r.line(dim("  · it is still working — /cancel to interrupt"));
      return prompt();
    }
    wire.send({ jsonrpc: "2.0", id: nextId++, method: "session/prompt", params: { sessionId, prompt: [{ type: "text", text: line }] } });
    busy = true;
    prompt();
  });

  rl.on("SIGINT", () => {
    if (busy) {
      wire.send({ jsonrpc: "2.0", id: nextId++, method: "session/cancel", params: { sessionId } });
      r.line(dim("  · cancelling…"));
      return prompt();
    }
    wire.close();
    rl.close();
    process.exit(0);
  });

  return new Promise<number>(() => {
    /* runs until the socket closes or the user leaves */
  });
}
