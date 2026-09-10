// ACP ON STDIO — the agent view's conversation, for a client that is not a browser.
//
// The agent view is an ACP session: `iso-acp-bridge.mjs` spawns the harness, speaks ACP to it over
// stdio, and FANS THE SESSION OUT to N WebSocket clients. The doorman-served page is one of them.
// This is another — it just happens to have a terminal on one side instead of a canvas:
//
//   ssh -s acp <routeId>@ssh.isolation.cc
//     → the bastion execs THIS in the sandbox
//     → it joins the same bridge the browser is on
//     → the client's stdin/stdout carry the same JSON-RPC the browser's socket carries
//
// So an external ACP client drives the SAME conversation the session screen is showing, live and
// both ways, with no relay and no second agent. Nothing is copied, nothing is summarised: the
// bridge's replay buffer means a late joiner is handed the whole session on connect.
//
// NEWLINE-DELIMITED JSON both ways, which is the framing ACP itself uses over stdio — so a client
// that already speaks ACP to a subprocess needs no adapter, and `ssh -s acp …` is a working "agent
// command" wherever one is configured.
//
// WHY A HAND-WRITTEN WEBSOCKET CLIENT: the same reason the bridge hand-writes the server. This runs
// on the sandbox's bundled Node with no npm install and nothing on disk but what we wrote there, so
// a dependency is not available at the moment it would be needed. RFC 6455's client half is ~80
// lines and all of it is here.
import net from "node:net";
import { randomBytes, createHash } from "node:crypto";

const PORT = Number(process.env.ISO_ACP_PORT || process.argv[2] || 0);
const HOST = "127.0.0.1";
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// stderr, never stdout: stdout is the protocol, and one stray log line corrupts the stream.
const log = (...a) => process.stderr.write(`[acp-attach] ${a.join(" ")}\n`);

if (!PORT) {
  log("no bridge port — the view may not be running");
  process.exit(2);
}

const sock = net.connect(PORT, HOST);
sock.on("error", (e) => {
  log(`cannot reach the agent view: ${e.message}`);
  process.exit(1);
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
      process.exit(1);
    }
    // The accept header is what proves we are talking to a WebSocket server and not to something
    // that merely answered 101 — cheap, and the only integrity the handshake offers.
    const accept = /sec-websocket-accept:\s*(\S+)/i.exec(head)?.[1];
    if (accept !== expectAccept) {
      log("the agent view's handshake did not verify");
      process.exit(1);
    }
    handshaken = true;
  }
  drainFrames();
});

sock.on("close", () => {
  // A closed bridge is the end of the conversation, not an error: the view was deleted, or the
  // session finished. Exit 0 so an `ssh` that ends this way does not look like a failure.
  process.exit(0);
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
      send(0xa, payload); // pong, echoing the payload as the RFC asks
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

function emit(opcode, payload) {
  if (opcode !== 0x1) return; // binary is not part of this protocol
  // ONE MESSAGE PER LINE, and the payload must not contain one of its own: the bridge sends
  // `JSON.stringify` output, which escapes every newline inside strings, so a raw write is safe.
  process.stdout.write(payload.toString("utf8").replace(/\r?\n/g, " ") + "\n");
}

function bail(why) {
  if (why) log(why);
  try {
    sock.destroy();
  } catch {
    /* already gone */
  }
  process.exit(why ? 1 : 0);
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
process.stdin.on("data", (d) => {
  inbuf += d.toString("utf8");
  for (;;) {
    const nl = inbuf.indexOf("\n");
    if (nl === -1) break;
    const line = inbuf.slice(0, nl).trim();
    inbuf = inbuf.slice(nl + 1);
    if (!line) continue;
    if (!handshaken) {
      // Before the upgrade completes there is nowhere to put it. Dropping a client's first request
      // would look like the agent ignoring it, so wait rather than discard.
      inbuf = `${line}\n${inbuf}`;
      setTimeout(() => process.stdin.emit("data", Buffer.alloc(0)), 25);
      break;
    }
    send(0x1, Buffer.from(line, "utf8"));
  }
});
process.stdin.on("end", () => bail(null));
