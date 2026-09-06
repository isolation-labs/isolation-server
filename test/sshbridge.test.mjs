// The ssh transport, both halves, without a sandbox: the host-side WebSocket client
// (dist/wsframe.js + the sshfwd splice) against the real in-sandbox bridge script running on this
// host's Node, with a plain TCP echo server standing in for sshd.
//
// Framing is where the subtle bugs live — a frame can span TCP reads and one read can carry
// several — so the decoders are fed deliberately awkward splits, and the loopback pushes enough
// bytes through to fragment for real.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, connect } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

process.env.ISOLATION_SERVER_HOME ??= mkdtempSync(join(tmpdir(), "iso-ssh-test-"));

const ROOT = new URL("..", import.meta.url).pathname;
const BRIDGE = join(ROOT, "sandbox", "iso-ws-bridge.mjs");

const host = await import("../dist/wsframe.js");
const bridge = await import("../sandbox/iso-ws-bridge.mjs");
const { spliceOverWs } = await import("../dist/sshfwd.js");

const freePort = () =>
  new Promise((resolve) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

// --- framing -------------------------------------------------------------------

test("a masked client frame decodes to its payload, however the bytes arrive", () => {
  const payload = randomBytes(300);
  const frame = host.encodeFrame(0x2, payload, true);
  // Whole, then one byte at a time — the pathological fragmentation of a slow proxy.
  assert.deepEqual(new bridge.FrameDecoder().push(frame).map((f) => f.payload), [payload]);
  const dec = new bridge.FrameDecoder();
  const out = [];
  for (const b of frame) out.push(...dec.push(Buffer.from([b])));
  assert.equal(out.length, 1, "one frame, no matter the split");
  assert.deepEqual(out[0].payload, payload);
  assert.equal(out[0].opcode, 0x2);
});

test("several frames in one read, and a frame split across two", () => {
  const a = randomBytes(10);
  const b = randomBytes(70000); // forces the 64-bit length header
  const c = randomBytes(200); // 16-bit header
  const buf = Buffer.concat([bridge.encodeFrame(0x2, a), bridge.encodeFrame(0x2, b), bridge.encodeFrame(0x2, c)]);
  const dec = new host.FrameDecoder();
  const cut = 8; // mid-header of the first frame
  const got = [...dec.push(buf.subarray(0, cut)), ...dec.push(buf.subarray(cut))];
  assert.deepEqual(got.map((f) => f.payload), [a, b, c]);
});

test("an empty frame and a control frame survive the round trip", () => {
  const dec = new bridge.FrameDecoder();
  const frames = dec.push(Buffer.concat([host.encodeFrame(0x9, Buffer.alloc(0), true), host.encodeFrame(0x2, Buffer.from("hi"), true), host.encodeFrame(0x8, Buffer.alloc(0), true)]));
  assert.deepEqual(frames.map((f) => f.opcode), [0x9, 0x2, 0x8]);
  assert.equal(frames[1].payload.toString(), "hi");
});

test("an impossible length is rejected rather than buffered forever", () => {
  const bad = Buffer.alloc(10);
  bad[0] = 0x82;
  bad[1] = 127;
  bad.writeUInt32BE(1, 2); // > 2^32 bytes of payload
  assert.throws(() => new host.FrameDecoder().push(bad), /too large/);
});

test("both sides compute the same handshake accept", () => {
  assert.equal(host.acceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455 vector");
  assert.equal(bridge.acceptKey("dGhlIHNhbXBsZSBub25jZQ=="), host.acceptKey("dGhlIHNhbXBsZSBub25jZQ=="));
});

// --- the whole pipe ------------------------------------------------------------

test("ssh bytes survive the full splice: tcp → ws → bridge → tcp and back", async (t) => {
  // sshd's stand-in: echoes every byte back.
  const echo = createServer((c) => c.pipe(c));
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const targetPort = echo.address().port;
  const bridgePort = await freePort();
  const pidFile = join(process.env.ISOLATION_SERVER_HOME, "bridge.pid");

  const proc = spawn(process.execPath, [BRIDGE, String(bridgePort), String(targetPort), pidFile], { stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve, reject) => {
    proc.stdout.once("data", resolve);
    proc.once("error", reject);
    setTimeout(() => reject(new Error("bridge did not start")), 5000).unref();
  });

  // The host end, exactly as sshfwd wires it: a local TCP listener whose connections are spliced
  // over a WebSocket to the bridge.
  const front = createServer((client) => {
    client.pause();
    host
      .wsConnect({ host: `127.0.0.1:${bridgePort}`, path: "/" })
      .then(({ socket, head }) => spliceOverWs(client, socket, head))
      .catch(() => client.destroy());
  });
  await new Promise((r) => front.listen(0, "127.0.0.1", r));

  t.after(() => {
    proc.kill();
    front.close();
    echo.close();
  });

  // 2 MB in many writes: enough to fragment, to fill a socket buffer (backpressure) and to cross
  // every length-header boundary.
  const sent = randomBytes(2 * 1024 * 1024);
  const received = await new Promise((resolve, reject) => {
    const c = connect(front.address().port, "127.0.0.1");
    const chunks = [];
    let got = 0;
    c.on("data", (d) => {
      chunks.push(d);
      got += d.length;
      if (got >= sent.length) {
        c.end();
        resolve(Buffer.concat(chunks));
      }
    });
    c.on("error", reject);
    c.on("connect", () => {
      for (let i = 0; i < sent.length; i += 64 * 1024) c.write(sent.subarray(i, i + 64 * 1024));
    });
    setTimeout(() => reject(new Error("timed out waiting for the echo")), 20000).unref();
  });
  assert.equal(received.length, sent.length);
  assert.ok(received.equals(sent), "every byte, in order — a stream corrupted here looks like an ssh protocol error");
});

test("the bridge refuses a non-WebSocket request instead of hanging", async (t) => {
  const bridgePort = await freePort();
  const proc = spawn(process.execPath, [BRIDGE, String(bridgePort), "1", join(process.env.ISOLATION_SERVER_HOME, "bridge2.pid")], { stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve, reject) => {
    proc.stdout.once("data", resolve);
    proc.once("error", reject);
    setTimeout(() => reject(new Error("bridge did not start")), 5000).unref();
  });
  t.after(() => proc.kill());
  const res = await fetch(`http://127.0.0.1:${bridgePort}/`);
  assert.equal(res.status, 426);
  await res.text();
  // And a handshake to a dead target still upgrades, then closes — never a silent hang.
  await assert.doesNotReject(host.wsConnect({ host: `127.0.0.1:${bridgePort}`, path: "/" }).then(({ socket }) => socket.destroy()));
});

process.on("exit", () => rmSync(process.env.ISOLATION_SERVER_HOME, { recursive: true, force: true }));
