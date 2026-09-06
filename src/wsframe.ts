// WebSocket framing, host side — the client half of the ssh transport.
//
// Why by hand: the sandbox's ssh daemon is reachable ONLY through execd's proxy, which carries
// HTTP and WebSocket and nothing else (see sshfwd.ts), so the splice has to speak WS. Node 20 has
// no stable WebSocket client (the global is experimental there and cannot carry execd's auth
// headers anyway), and isolation-server keeps its dependency list to one entry — so the handshake
// and RFC 6455 framing live here. Only what the splice needs: binary frames, ping/pong, close.
import { createHash, randomBytes } from "node:crypto";
import { request } from "node:http";
import type { Socket } from "node:net";

export const OP_BINARY = 0x2;
export const OP_CLOSE = 0x8;
export const OP_PING = 0x9;
export const OP_PONG = 0xa;

// RFC 6455's fixed handshake salt.
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// A frame bigger than this is a peer that has lost the plot (ours never sends one — the splice
// writes whatever a TCP read produced, tens of KB). Cap it so a corrupt length header can't make
// us buffer gigabytes waiting for a payload that never arrives.
const MAX_PAYLOAD = 16 * 1024 * 1024;

export const acceptKey = (key: string): string => createHash("sha1").update(key + GUID).digest("base64");

export interface Frame {
  fin: boolean;
  opcode: number;
  payload: Buffer;
}

/** One frame, unfragmented. `mask` per the spec: client→server frames must be masked, server→client must not. */
export function encodeFrame(opcode: number, payload: Buffer, mask: boolean): Buffer {
  const len = payload.length;
  if (len > MAX_PAYLOAD) throw new Error("ws frame too large");
  const head = len < 126 ? 2 : len < 65536 ? 4 : 10;
  const out = Buffer.allocUnsafe(head + (mask ? 4 : 0) + len);
  out[0] = 0x80 | opcode; // FIN — we never fragment on send
  out[1] = (mask ? 0x80 : 0) | (len < 126 ? len : len < 65536 ? 126 : 127);
  if (len >= 126 && len < 65536) out.writeUInt16BE(len, 2);
  else if (len >= 65536) {
    out.writeUInt32BE(0, 2); // 64-bit length, high word — MAX_PAYLOAD keeps it zero
    out.writeUInt32BE(len, 6);
  }
  if (mask) {
    const key = randomBytes(4);
    key.copy(out, head);
    for (let i = 0; i < len; i++) out[head + 4 + i] = payload[i] ^ key[i & 3];
  } else {
    payload.copy(out, head);
  }
  return out;
}

/**
 * Streaming frame decoder. A frame can span several TCP reads and one read can carry several
 * frames — feeding raw chunks to a parser that assumes either is the classic way to corrupt an
 * ssh stream into what looks like a protocol error. So: buffer, and only emit whole frames.
 */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);

  /** Every complete frame the chunk finished. Throws on a frame that could never be valid. */
  push(chunk: Buffer): Frame[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: Frame[] = [];
    for (;;) {
      const f = this.next();
      if (!f) return out;
      out.push(f);
    }
  }

  private next(): Frame | null {
    const b = this.buf;
    if (b.length < 2) return null;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      if (b.readUInt32BE(2) !== 0) throw new Error("ws frame too large");
      len = b.readUInt32BE(6);
      off = 10;
    }
    if (len > MAX_PAYLOAD) throw new Error("ws frame too large");
    const need = off + (masked ? 4 : 0) + len;
    if (b.length < need) return null;
    const payload = Buffer.from(b.subarray(off + (masked ? 4 : 0), need));
    if (masked) {
      const key = b.subarray(off, off + 4);
      for (let i = 0; i < len; i++) payload[i] ^= key[i & 3];
    }
    // Copy the tail rather than keeping a view: a subarray pins the whole concatenated buffer
    // alive for as long as the leftovers live.
    this.buf = b.length === need ? Buffer.alloc(0) : Buffer.from(b.subarray(need));
    return { fin: (b[0] & 0x80) !== 0, opcode: b[0] & 0x0f, payload };
  }
}

/**
 * Open a WebSocket to `http://<host><path>`, carrying `headers` verbatim (execd's access token
 * rides there — dropping it turns every ssh connection into a 401). Resolves with the raw socket,
 * already upgraded, plus whatever bytes arrived alongside the 101.
 */
export function wsConnect(opts: { host: string; path: string; headers?: Record<string, string>; timeoutMs?: number }): Promise<{ socket: Socket; head: Buffer }> {
  return new Promise((resolve, reject) => {
    const key = randomBytes(16).toString("base64");
    const req = request(`http://${opts.host}${opts.path}`, {
      headers: {
        ...(opts.headers ?? {}),
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
      },
    });
    let settled = false;
    const fail = (e: Error) => {
      if (settled) return; // after the upgrade the socket is the caller's — never destroy it here
      settled = true;
      req.destroy();
      reject(e);
    };
    req.setTimeout(opts.timeoutMs ?? 15_000, () => fail(new Error("ws handshake timed out")));
    req.on("error", fail);
    // A plain response means no upgrade happened: execd answers a dead in-sandbox port with a 502
    // RESPONSE rather than a connection error, so this is the "the bridge isn't running" path.
    req.on("response", (res) => {
      res.resume();
      fail(new Error(`ws upgrade refused: HTTP ${res.statusCode}`));
    });
    req.on("upgrade", (res, socket, head) => {
      if (res.headers["sec-websocket-accept"] !== acceptKey(key)) {
        socket.destroy();
        return fail(new Error("ws handshake: bad accept"));
      }
      settled = true;
      socket.setTimeout(0);
      socket.setNoDelay(true);
      socket.setKeepAlive(true, 30_000);
      resolve({ socket, head: head ?? Buffer.alloc(0) });
    });
    req.end();
  });
}
