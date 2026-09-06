// The in-sandbox half of ssh access: a WebSocket server that splices each connection to a local
// TCP port (sshd on 2222).
//
// WHY IT EXISTS: the runtime publishes exactly two container ports to the host, and everything
// else is reachable only through execd's proxy — an HTTP reverse proxy that passes WebSocket
// upgrades through. sshd speaks neither, so a WS→TCP hop in front of it is what makes native
// `ssh` possible at all. isolation-server's sshfwd is the mirror image on the host side; between
// them the user's ssh client sees an ordinary TCP port.
//
// Dependency-free on purpose (the tooling image ships a bare Node as `iso-node` and nothing else),
// so the RFC 6455 handshake and framing are hand-rolled here. Only the frames a byte stream needs:
// binary/continuation data, ping/pong, close.
import { createServer } from "node:http";
import net from "node:net";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_PAYLOAD = 16 * 1024 * 1024;

export const acceptKey = (key) => createHash("sha1").update(key + GUID).digest("base64");

/** One unfragmented frame. The server never masks (the spec forbids it server→client). */
export function encodeFrame(opcode, payload, mask = false) {
  const len = payload.length;
  const head = len < 126 ? 2 : len < 65536 ? 4 : 10;
  const out = Buffer.allocUnsafe(head + (mask ? 4 : 0) + len);
  out[0] = 0x80 | opcode;
  out[1] = (mask ? 0x80 : 0) | (len < 126 ? len : len < 65536 ? 126 : 127);
  if (len >= 126 && len < 65536) out.writeUInt16BE(len, 2);
  else if (len >= 65536) { out.writeUInt32BE(0, 2); out.writeUInt32BE(len, 6); }
  if (mask) {
    const key = Buffer.allocUnsafe(4);
    for (let i = 0; i < 4; i++) key[i] = (Math.random() * 256) | 0;
    key.copy(out, head);
    for (let i = 0; i < len; i++) out[head + 4 + i] = payload[i] ^ key[i & 3];
  } else {
    payload.copy(out, head);
  }
  return out;
}

/** Streaming decoder: frames fragment across TCP reads and several can share one read. */
export class FrameDecoder {
  #buf = Buffer.alloc(0);
  push(chunk) {
    this.#buf = this.#buf.length ? Buffer.concat([this.#buf, chunk]) : chunk;
    const out = [];
    for (;;) {
      const f = this.#next();
      if (!f) return out;
      out.push(f);
    }
  }
  #next() {
    const b = this.#buf;
    if (b.length < 2) return null;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) { if (b.length < 4) return null; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) {
      if (b.length < 10) return null;
      if (b.readUInt32BE(2) !== 0) throw new Error("ws frame too large");
      len = b.readUInt32BE(6); off = 10;
    }
    if (len > MAX_PAYLOAD) throw new Error("ws frame too large");
    const need = off + (masked ? 4 : 0) + len;
    if (b.length < need) return null;
    const payload = Buffer.from(b.subarray(off + (masked ? 4 : 0), need));
    if (masked) {
      const key = b.subarray(off, off + 4);
      for (let i = 0; i < len; i++) payload[i] ^= key[i & 3];
    }
    this.#buf = b.length === need ? Buffer.alloc(0) : Buffer.from(b.subarray(need));
    return { fin: (b[0] & 0x80) !== 0, opcode: b[0] & 0x0f, payload };
  }
}

/** Splice an upgraded WebSocket to `127.0.0.1:<target>`; resolves when both halves are closed. */
export function spliceToTcp(ws, target, head) {
  // A client that vanishes right after the 101 has already emitted 'close', so the handlers below
  // would never run and the TCP half would sit open against sshd. Cheaper to notice here.
  if (ws.destroyed) return;
  const up = net.connect(target, "127.0.0.1");
  up.setNoDelay(true);
  ws.setNoDelay(true);
  const dec = new FrameDecoder();
  let closed = false;
  const bye = () => {
    if (closed) return;
    closed = true;
    ws.destroy();
    up.destroy();
  };
  const onWsData = (chunk) => {
    let frames;
    try {
      frames = dec.push(chunk);
    } catch {
      return bye();
    }
    for (const f of frames) {
      if (f.opcode === 0x8) return bye();
      if (f.opcode === 0x9) { ws.write(encodeFrame(0xa, f.payload)); continue; }
      if (f.opcode === 0xa) continue;
      // 0x0/0x1/0x2 all carry stream bytes; order is what matters, not the boundaries.
      up.write(f.payload);
    }
    // One drain listener per stall, never one per frame (a full chunk can hold many).
    if (up.writableNeedDrain && !ws.isPaused()) { ws.pause(); up.once("drain", () => ws.resume()); }
  };
  if (head && head.length) onWsData(head);
  ws.on("data", onWsData);
  up.on("data", (chunk) => {
    if (!ws.write(encodeFrame(0x2, chunk))) { up.pause(); ws.once("drain", () => up.resume()); }
  });
  for (const s of [ws, up]) { s.on("error", bye); s.on("close", bye); s.on("end", bye); }
}

function main() {
  const [listenPort, targetPort, pidFile] = process.argv.slice(2);
  const server = createServer((_req, res) => { res.writeHead(426); res.end("upgrade required"); });
  server.on("upgrade", (req, sock, head) => {
    // node's http server REMOVES its own 'error' listener before emitting 'upgrade', so from here
    // the socket is bare: a peer that resets while we write the 101 (or the 400 below) would emit
    // an unhandled 'error' and take the bridge down, and with it ssh for the whole sandbox.
    sock.on("error", () => sock.destroy());
    const key = req.headers["sec-websocket-key"];
    if (!key || (req.headers.upgrade ?? "").toLowerCase() !== "websocket") {
      sock.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return sock.destroy();
    }
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`);
    spliceToTcp(sock, Number(targetPort), head);
  });
  server.on("clientError", (_e, sock) => sock.destroy());
  // 0.0.0.0, like the web-view forwarder: execd reaches in-sandbox ports over the container's own
  // address, not loopback. Nothing is published to the host, and sshd behind it is key-only.
  server.listen(Number(listenPort), "0.0.0.0", () => {
    // The pidfile is how the server stops a previous bridge. `pkill -f` cannot be used: the shell
    // running it carries the pattern in its own command line and kills itself first.
    if (pidFile) { try { writeFileSync(pidFile, String(process.pid)); } catch { /* best effort */ } }
    console.log(`iso-ws-bridge ${listenPort} -> 127.0.0.1:${targetPort}`);
  });
}

// Importable for tests; runs only when executed as a script.
if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) main();
