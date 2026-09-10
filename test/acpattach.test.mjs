// THE ACP STDIO ATTACH (`sandbox/iso-acp-attach.mjs`) — the agent view's external door.
//
// This is a hand-written RFC 6455 CLIENT, and every part of it fails silently when it is wrong: an
// unmasked frame is dropped by a compliant server, a mishandled length reads the next frame's header
// as payload, and a fragmented message arrives as half a JSON document. None of that throws — the
// conversation simply stops making sense. So the test drives the real script against a real socket
// and checks the bytes.
//
// The fake server here is deliberately NOT the bridge: what is under test is the client half, and
// borrowing the bridge's framing to test the client would make one bug in a shared helper look like
// agreement.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import net from "node:net";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../sandbox/iso-acp-attach.mjs", import.meta.url));
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** A WebSocket server that speaks only what the bridge speaks, and records what the client sends. */
function fakeBridge() {
  const received = [];
  let sock;
  let onFrame = () => {};
  const server = net.createServer((s) => {
    sock = s;
    let buf = Buffer.alloc(0);
    let up = false;
    s.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (!up) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = buf.subarray(0, end).toString("latin1");
        buf = buf.subarray(end + 4);
        const key = /sec-websocket-key:\s*(\S+)/i.exec(head)?.[1] ?? "";
        const accept = createHash("sha1").update(key + GUID).digest("base64");
        s.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
        up = true;
      }
      // Read client frames. A CLIENT MUST MASK, so an unmasked one is a bug we want to see.
      for (;;) {
        if (buf.length < 2) return;
        const masked = (buf[1] & 0x80) !== 0;
        let len = buf[1] & 0x7f;
        let off = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          off = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          off = 10;
        }
        assert.equal(masked, true, "a client frame must be masked");
        if (buf.length < off + 4 + len) return;
        const mask = buf.subarray(off, off + 4);
        const body = Buffer.from(buf.subarray(off + 4, off + 4 + len));
        for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4];
        buf = buf.subarray(off + 4 + len);
        received.push(body.toString("utf8"));
        onFrame(body.toString("utf8"));
      }
    });
  });
  return {
    server,
    received,
    onFrame: (fn) => (onFrame = fn),
    /** Send one text message, optionally split across `parts` continuation frames. */
    send(text, parts = 1) {
      const payload = Buffer.from(text, "utf8");
      const size = Math.ceil(payload.length / parts);
      for (let i = 0; i < parts; i++) {
        const slice = payload.subarray(i * size, Math.min((i + 1) * size, payload.length));
        const fin = i === parts - 1;
        const opcode = i === 0 ? 0x1 : 0x0;
        const head = slice.length < 126 ? Buffer.alloc(2) : slice.length < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
        head[0] = (fin ? 0x80 : 0) | opcode;
        if (slice.length < 126) head[1] = slice.length;
        else if (slice.length < 65536) {
          head[1] = 126;
          head.writeUInt16BE(slice.length, 2);
        } else {
          head[1] = 127;
          head.writeBigUInt64BE(BigInt(slice.length), 2);
        }
        sock.write(Buffer.concat([head, slice]));
      }
    },
    close: () => sock?.destroy(),
  };
}

const listen = (server) => new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));

/** Run the attach script against a fake bridge, and give the test both ends. */
async function withAttach(fn) {
  const bridge = fakeBridge();
  const port = await listen(bridge.server);
  const child = spawn(process.execPath, [SCRIPT, String(port)], { stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let out = "";
  child.stdout.on("data", (d) => {
    out += d.toString("utf8");
    for (;;) {
      const nl = out.indexOf("\n");
      if (nl === -1) break;
      lines.push(out.slice(0, nl));
      out = out.slice(nl + 1);
    }
  });
  const nextLine = async () => {
    for (let i = 0; i < 200 && !lines.length; i++) await new Promise((r) => setTimeout(r, 10));
    return lines.shift();
  };
  const nextFrame = () =>
    new Promise((resolve) => {
      bridge.onFrame((t) => resolve(t));
    });
  try {
    await fn({ bridge, child, nextLine, nextFrame, lines });
  } finally {
    child.kill("SIGKILL");
    bridge.server.close();
  }
}

test("the handshake completes, and a text frame becomes one line on stdout", async () => {
  await withAttach(async ({ bridge, nextLine }) => {
    // Give the handshake a moment — the script writes its GET on connect.
    await new Promise((r) => setTimeout(r, 100));
    bridge.send(JSON.stringify({ jsonrpc: "2.0", method: "_iso/hello", params: { viewId: "v-1" } }));
    const line = await nextLine();
    assert.ok(line, "the client emitted a line");
    assert.equal(JSON.parse(line).method, "_iso/hello");
  });
});

test("a line on stdin becomes one MASKED frame — an unmasked one is dropped by a real server", async () => {
  await withAttach(async ({ child, nextFrame }) => {
    await new Promise((r) => setTimeout(r, 100));
    const waiting = nextFrame();
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "session/prompt", params: { prompt: [] } })}\n`);
    const got = await waiting;
    // The masking assertion lives in the fake server, which fails the test if a frame arrives raw.
    assert.equal(JSON.parse(got).method, "session/prompt");
  });
});

test("a message split across continuation frames arrives as ONE line", async () => {
  // `_iso/hello` carries the whole replay buffer, which for a real conversation is far past what any
  // server puts in a single frame. Reassembled wrong, a client gets half a JSON document.
  await withAttach(async ({ bridge, nextLine }) => {
    await new Promise((r) => setTimeout(r, 100));
    const big = { jsonrpc: "2.0", method: "_iso/hello", params: { updates: Array.from({ length: 400 }, (_, i) => ({ i, text: "x".repeat(200) })) } };
    const text = JSON.stringify(big);
    assert.ok(text.length > 65536, "the fixture is past a 16-bit length, which is the case that breaks");
    bridge.send(text, 7);
    const line = await nextLine();
    const parsed = JSON.parse(line);
    assert.equal(parsed.params.updates.length, 400, "every fragment landed, in order");
  });
});

test("a message the client sends that is past 64KB is framed with a 64-bit length", async () => {
  await withAttach(async ({ child, nextFrame }) => {
    await new Promise((r) => setTimeout(r, 100));
    const waiting = nextFrame();
    const text = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "session/prompt", params: { prompt: [{ type: "text", text: "y".repeat(70000) }] } });
    child.stdin.write(`${text}\n`);
    const got = await waiting;
    assert.equal(got.length, text.length, "the whole message arrived, masked, in one frame");
  });
});

test("a bridge that closes ends the client cleanly — an ended session is not a failure", async () => {
  await withAttach(async ({ bridge, child }) => {
    await new Promise((r) => setTimeout(r, 100));
    const exited = new Promise((r) => child.on("exit", (code) => r(code)));
    bridge.close();
    assert.equal(await exited, 0, "exit 0, so `ssh` does not report a failure when the view simply ended");
  });
});

test("a server that is not a WebSocket is refused rather than half-spoken to", async () => {
  const server = net.createServer((s) => {
    s.on("data", () => s.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));
  });
  const port = await listen(server);
  const child = spawn(process.execPath, [SCRIPT, String(port)], { stdio: ["pipe", "pipe", "pipe"] });
  const code = await new Promise((r) => child.on("exit", (c) => r(c)));
  server.close();
  assert.equal(code, 1, "a non-101 answer is fatal, not something to keep writing frames into");
});
