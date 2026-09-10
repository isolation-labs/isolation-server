// ACP ON STDIO — the agent view's conversation, for a client that is not a browser.
//
// The agent view is an ACP session: `iso-acp-bridge.mjs` spawns the harness, speaks ACP to it over
// stdio, and FANS THE SESSION OUT to N WebSocket clients. The doorman-served page is one of them.
// This is another — it just happens to have a terminal on one side instead of a canvas:
//
//   ssh -s <routeId>@ssh.isolation.cc acp        (`-s` takes the subsystem in the command slot)
//     → the bastion execs THIS in the sandbox
//     → it joins the same bridge the browser is on
//     → the client's stdin/stdout carry the same JSON-RPC the browser's socket carries
//
// So an external ACP client drives the SAME conversation the session screen is showing, live and
// both ways, with no relay and no second agent. Nothing is copied, nothing is summarised: the
// bridge's replay buffer means a late joiner is handed the whole session on connect.
//
// NEWLINE-DELIMITED JSON both ways, which is the framing ACP itself uses over stdio — so a client
// that already speaks ACP to a subprocess needs no adapter, and `ssh -s … acp` is a working "agent
// command" wherever one is configured.
//
// WHY A HAND-WRITTEN WEBSOCKET CLIENT: the same reason the bridge hand-writes the server. This runs
// on the sandbox's bundled Node with no npm install and nothing on disk but what we wrote there, so
// a dependency is not available at the moment it would be needed. RFC 6455's client half is ~80
// lines and all of it is here.
import net from "node:net";
import { randomBytes, createHash } from "node:crypto";
import { StringDecoder } from "node:string_decoder";

const PORT = Number(process.env.ISO_ACP_PORT || process.argv[2] || 0);
// WHICH VIEW THIS PORT IS SUPPOSED TO BE. A PORT IS NOT IDENTITY: view ports are handed out from
// the free ones (launch.ts `nextFree` only avoids LIVE views) and a bridge orphaned by a deleted
// view is never killed, so another agent's bridge can be sitting on this number — answering
// happily, and handing whoever asks its whole conversation. The doorman makes exactly this check
// on the browser's path (`bridgeHealthy`); an ssh client needs it just as much. Empty = unchecked,
// which is only ever the case when this is run by hand.
const VIEW_ID = process.env.ISO_ACP_VIEW || process.argv[3] || "";
const HOST = "127.0.0.1";
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// stderr, never stdout: stdout is the protocol, and one stray log line corrupts the stream.
const log = (...a) => process.stderr.write(`[acp-attach] ${a.join(" ")}\n`);

if (!PORT) {
  log("no bridge port — the view may not be running");
  process.exit(2);
}

// ── Leaving ────────────────────────────────────────────────────────────────────────────────────
//
// OUR STDOUT IS A PIPE — the ssh channel — so writes to it are ASYNCHRONOUS, and `process.exit`
// throws away whatever is still queued. That is not a corner case here: the bridge's `_iso/hello`
// carries the whole replay buffer, and a client that reads at its own pace (any real ACP client,
// over a network) leaves hundreds of kilobytes buffered on our side. A bridge that then closes —
// a deleted view, a finished session — would deliver NOTHING. So an exit waits for what we already
// wrote to actually leave, and only the timeout is allowed to give up on it.
let pending = 0;
let leaving = null;

function out(line) {
  pending++;
  process.stdout.write(line, () => {
    if (--pending === 0 && leaving !== null) process.exit(leaving);
  });
}

function finish(code) {
  if (leaving !== null) return; // already on the way out; the first reason is the real one
  leaving = code;
  try {
    sock.destroy();
  } catch {
    /* already gone */
  }
  process.stdin.pause(); // nothing left to send it to, and it would hold the loop open
  if (pending === 0) process.exit(code);
  // A peer that stopped reading must not keep this alive forever. NOT unref'd: the point is a
  // guaranteed exit, with this code rather than whatever an emptied event loop would report.
  setTimeout(() => process.exit(code), 10_000);
}

// THE CLIENT HANGING UP IS THE ORDINARY ENDING, not a crash. Our stdio IS the ssh channel, so when
// the client disconnects mid-write the pipe breaks under us — and an EPIPE on `process.stdout` with
// no listener is an uncaught exception, which turns a normal goodbye into a stack trace and a
// nonzero exit. Node still runs the pending write callbacks with the error, so `finish` drains and
// exits as it would have anyway.
process.stdout.on("error", () => finish(0));
process.stdin.on("error", () => finish(0));

const sock = net.connect(PORT, HOST);
sock.on("error", (e) => {
  log(`cannot reach the agent view: ${e.message}`);
  finish(1);
});

// ── The handshake ──────────────────────────────────────────────────────────────────────────────

const key = randomBytes(16).toString("base64");
const expectAccept = createHash("sha1").update(key + GUID).digest("base64");
let handshaken = false;
let buf = Buffer.alloc(0);

sock.on("connect", () => {
  sock.write(
    [
      "GET / HTTP/1.1",
      `Host: ${HOST}:${PORT}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      "",
      "",
    ].join("\r\n"),
  );
});

sock.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  if (!handshaken) {
    const end = buf.indexOf("\r\n\r\n");
    if (end === -1) return; // headers still arriving
    const head = buf.subarray(0, end).toString("latin1");
    buf = buf.subarray(end + 4);
    if (!/^HTTP\/1\.1 101/i.test(head)) {
      log(`the agent view refused the connection: ${head.split("\r\n")[0]}`);
      return finish(1);
    }
    // The accept header is what proves we are talking to a WebSocket server and not to something
    // that merely answered 101 — cheap, and the only integrity the handshake offers.
    const accept = /sec-websocket-accept:\s*(\S+)/i.exec(head)?.[1];
    if (accept !== expectAccept) {
      log("the agent view's handshake did not verify");
      return finish(1);
    }
    handshaken = true;
  }
  drainFrames();
});

sock.on("close", () => {
  // A closed bridge is the end of the conversation, not an error: the view was deleted, or the
  // session finished. Exit 0 so an `ssh` that ends this way does not look like a failure — once
  // everything it already said has reached the client (see `finish`).
  finish(0);
});

// ── Frames in ──────────────────────────────────────────────────────────────────────────────────

// Fragmentation is real here: the bridge's `_iso/hello` carries the whole replay buffer, which for a
// long conversation is far past any single frame a sane server emits in one write.
let fragments = [];
let fragmentOp = 0;

function drainFrames() {
  for (;;) {
    if (buf.length < 2) return;
    const b0 = buf[0];
    const b1 = buf[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let off = 2;
    if (len === 126) {
      if (buf.length < off + 2) return;
      len = buf.readUInt16BE(off);
      off += 2;
    } else if (len === 127) {
      if (buf.length < off + 8) return;
      const big = buf.readBigUInt64BE(off);
      // A frame that cannot be indexed is a frame we cannot handle; refuse rather than truncate.
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) return void bail("frame too large");
      len = Number(big);
      off += 8;
    }
    // A server MUST NOT mask (RFC 6455 §5.1). Handling it anyway costs four lines and makes this
    // work against a permissive peer rather than hanging on one.
    let mask;
    if (masked) {
      if (buf.length < off + 4) return;
      mask = buf.subarray(off, off + 4);
      off += 4;
    }
    if (buf.length < off + len) return; // the payload is still arriving
    let payload = buf.subarray(off, off + len);
    if (mask) {
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    }
    buf = buf.subarray(off + len);

    if (opcode === 0x8) return void bail(null); // close
    if (opcode === 0x9) {
      // Echo the payload as the RFC asks — capped at 125, because a control frame may not carry
      // more than that and `send` would otherwise emit an extended-length control frame, which is
      // exactly the malformed thing a compliant peer closes the connection over.
      send(0xa, payload.subarray(0, 125));
      continue;
    }
    if (opcode === 0xa) continue; // pong
    if (opcode === 0x0) {
      fragments.push(payload);
      if (!fin) continue;
      emit(fragmentOp, Buffer.concat(fragments));
      fragments = [];
      fragmentOp = 0;
      continue;
    }
    if (!fin) {
      fragmentOp = opcode;
      fragments = [payload];
      continue;
    }
    emit(opcode, payload);
  }
}

// The bridge sends `_iso/hello` to every client the moment it attaches, and that message NAMES ITS
// VIEW — so the first thing off the wire settles whether this is the conversation we were sent to
// join. Nothing reaches the client until it does: a wrong answer here is another agent's transcript.
let verified = !VIEW_ID;

function emit(opcode, payload) {
  if (opcode !== 0x1) return; // binary is not part of this protocol
  const text = payload.toString("utf8");
  if (!verified) {
    let named;
    try {
      const m = JSON.parse(text);
      named = m?.method === "_iso/hello" ? m?.params?.viewId : undefined;
    } catch {
      /* whatever answered is not our bridge */
    }
    if (named !== VIEW_ID) {
      log(`:${PORT} is not ${VIEW_ID}'s agent view (it says ${String(named ?? "nothing")}) — refusing rather than joining another conversation`);
      return void finish(1);
    }
    verified = true;
  }
  // ONE MESSAGE PER LINE, and the payload must not contain one of its own: the bridge sends
  // `JSON.stringify` output, which escapes every newline inside strings, so a raw write is safe.
  out(text.replace(/\r?\n/g, " ") + "\n");
}

function bail(why) {
  if (why) log(why);
  finish(why ? 1 : 0);
}

// ── Frames out ─────────────────────────────────────────────────────────────────────────────────

function send(opcode, payload) {
  const len = payload.length;
  const head = Buffer.alloc(len < 126 ? 6 : len < 65536 ? 8 : 14);
  head[0] = 0x80 | opcode;
  // A CLIENT MUST MASK every frame (RFC 6455 §5.3), and a compliant server closes the connection on
  // an unmasked one — so this is not optional politeness.
  const maskKey = randomBytes(4);
  if (len < 126) {
    head[1] = 0x80 | len;
    maskKey.copy(head, 2);
  } else if (len < 65536) {
    head[1] = 0x80 | 126;
    head.writeUInt16BE(len, 2);
    maskKey.copy(head, 4);
  } else {
    head[1] = 0x80 | 127;
    head.writeBigUInt64BE(BigInt(len), 2);
    maskKey.copy(head, 10);
  }
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= maskKey[i % 4];
  sock.write(Buffer.concat([head, body]));
}

// ── stdin → the bridge ─────────────────────────────────────────────────────────────────────────

let inbuf = "";
// A CHUNK BOUNDARY IS NOT A CHARACTER BOUNDARY: stdin arrives in pipe-sized pieces, and a prompt
// carrying anything outside ASCII (any accented word, any emoji, any CJK) will sooner or later be
// split mid-sequence. `Buffer.toString("utf8")` turns each half into U+FFFD, so the message the
// agent receives is quietly not the one that was typed. The decoder holds the partial sequence.
const stdinDecoder = new StringDecoder("utf8");
process.stdin.on("data", (d) => {
  if (leaving !== null) return; // on the way out: there is no socket left to send it to
  inbuf += stdinDecoder.write(d);
  for (;;) {
    const nl = inbuf.indexOf("\n");
    if (nl === -1) break;
    const line = inbuf.slice(0, nl).trim();
    inbuf = inbuf.slice(nl + 1);
    if (!line) continue;
    if (!handshaken || !verified) {
      // Before the upgrade completes — and before the bridge has named the view it is serving —
      // there is nowhere safe to put it. Dropping a client's first request would look like the
      // agent ignoring it, so wait rather than discard.
      inbuf = `${line}\n${inbuf}`;
      setTimeout(() => process.stdin.emit("data", Buffer.alloc(0)), 25);
      break;
    }
    send(0x1, Buffer.from(line, "utf8"));
  }
});
process.stdin.on("end", () => bail(null));
