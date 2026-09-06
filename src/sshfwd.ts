// SSH into a session, with the real `ssh` command.
//
// The runtime proxies HTTP and WebSocket only — never raw TCP — and it publishes exactly two
// container ports to the host (execd and 8080), a hardcoded list with no API to extend. So there
// is no TCP path to an in-sandbox sshd at all. What there is: execd's proxy, which passes
// WebSocket upgrades through. Hence the shape —
//
//   ssh -p 222xx → this listener → WS → execd /proxy/<bridge> → iso-ws-bridge → sshd:2222
//
// Both middle hops are ours and both live server-side, so the user's ssh client still speaks
// ordinary TCP to a local port. (sshd on 8080, the one spare published port, would be raw TCP —
// but only on Docker: the K8s ingress is HTTP/WS-only, so the bridge is the portable path.)
//
// WHY A PORT PER SESSION rather than one listener that routes: ssh offers no SNI, and the only
// routing signal — the username — lives inside the encrypted transport. Reading it means
// terminating ssh ourselves (an ssh2 server, a key store, a second auth model to get right). A
// port is the routing signal instead, and the CONTAINER's authorized_keys stays the only thing
// that decides who gets in: we move bytes and never see a key. That also means a session is
// exactly as reachable as its keys allow, with nothing here to misconfigure.
//
// Bound to loopback by default. A Cloud server (public IP) can bind its public interface instead
// so `ssh -p <port> root@<server>` works from anywhere; a connected server behind NAT needs the
// bastion in front, which is the same splice reached through a reverse tunnel.
import { createServer, type Server, type Socket } from "node:net";
import { endpointWithHeaders } from "./opensandbox.js";
import { SSH_BRIDGE_PORT } from "./launch.js";
import { encodeFrame, FrameDecoder, wsConnect, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG } from "./wsframe.js";

// The range sessions are handed ports from. Deliberately narrow and away from anything ephemeral,
// so a busy host can't collide with a listener we are about to open.
const PORT_BASE = 22200;
const PORT_MAX = 22299;
// Loopback unless told otherwise: publishing ssh is a deployment decision (a Cloud server with a
// public IP), never a default a laptop stumbles into.
const BIND = process.env.ISOLATION_SSH_BIND ?? "127.0.0.1";

interface Forwarder {
  port: number;
  server: Server;
  sockets: Set<Socket>;
}
const bySession = new Map<string, Forwarder>();

export function sshPortFor(sessionId: string): number | undefined {
  return bySession.get(sessionId)?.port;
}

/** Every session with ssh open, for status. */
export function sshForwarders(): Array<{ sessionId: string; port: number }> {
  return [...bySession].map(([sessionId, f]) => ({ sessionId, port: f.port }));
}

async function listenOnFreePort(onConn: (c: Socket) => void): Promise<{ server: Server; port: number } | null> {
  const taken = new Set([...bySession.values()].map((f) => f.port));
  for (let port = PORT_BASE; port <= PORT_MAX; port++) {
    if (taken.has(port)) continue;
    const server = createServer(onConn);
    const ok = await new Promise<boolean>((resolve) => {
      server.once("error", () => resolve(false)); // in use by something else on this host
      server.listen(port, BIND, () => resolve(true));
    });
    if (ok) {
      server.removeAllListeners("error");
      // A dead client socket must never take the listener down with it.
      server.on("error", () => {});
      return { server, port };
    }
    server.close();
  }
  return null;
}

/**
 * Open ssh for a session. Returns the port `ssh -p` should use, or null when ssh isn't available
 * (no sshd in the sandbox, or no free port). Idempotent: a session already forwarding keeps its
 * port, so a saved `ssh` command survives a restart of anything but this process.
 */
export async function openSsh(sessionId: string, sandboxId: string): Promise<number | null> {
  const existing = bySession.get(sessionId);
  if (existing) return existing.port;

  const sockets = new Set<Socket>();
  const started = await listenOnFreePort((client) => {
    sockets.add(client);
    // BEFORE anything can go wrong: an unhandled 'error' on a socket takes the whole process
    // down, and this one has no handler until the splice attaches its own — an HTTP round trip
    // to the runtime and a WebSocket upgrade later. An ssh client that hangs up in that window
    // (Ctrl-C, a port scanner, a probe against a Cloud server's public interface) resets the
    // connection and would otherwise kill isolation-server.
    client.on("error", () => client.destroy());
    client.on("close", () => sockets.delete(client));
    // Nothing may be read before the WebSocket is up: ssh sends its version banner the instant it
    // connects, and a socket that starts flowing here would drop those bytes on the floor.
    client.pause();
    client.setNoDelay(true);
    // Resolve the sandbox's endpoint PER CONNECTION: a resumed sandbox gets a new mapping, and
    // caching one would send ssh to a port that now belongs to something else. The headers matter
    // as much as the address — execd's access token rides there.
    endpointWithHeaders(sandboxId, SSH_BRIDGE_PORT)
      .then(({ host, basePath, headers }) => wsConnect({ host, path: `${basePath}/`, headers }))
      .then(({ socket: ws, head }) => spliceOverWs(client, ws, head))
      .catch(() => client.destroy());
  });
  if (!started) return null;

  bySession.set(sessionId, { port: started.port, server: started.server, sockets });
  return started.port;
}

/** Close a session's ssh listener and cut every live connection. Safe to call for a session that never had one. */
export function closeSsh(sessionId: string): void {
  const f = bySession.get(sessionId);
  if (!f) return;
  bySession.delete(sessionId);
  for (const s of f.sockets) s.destroy(); // close() alone waits for open connections forever
  f.server.close();
}

// Splice one ssh connection over an upgraded WebSocket: TCP bytes out as binary frames, frame
// payloads back into the socket. Either half ending ends the other; errors are expected (a client
// hanging up mid-handshake is routine) and must never reach the process. Exported so the tests can
// drive the real splice against the real bridge, with no sandbox in the way.
export function spliceOverWs(client: Socket, ws: Socket, head: Buffer): void {
  // Either end can already be gone: the WebSocket handshake is a round trip to the runtime, and an
  // ssh client that hangs up (or a `closeSsh` during it) has then ALREADY emitted 'close' — the
  // listeners below would never fire, so the surviving half would live on forever with its ping
  // timer, holding a proxy connection into the sandbox. One hung-up client per leak adds up fast on
  // a server that binds its public interface.
  if (client.destroyed || ws.destroyed) {
    client.destroy();
    ws.destroy();
    return;
  }
  const dec = new FrameDecoder();
  let closed = false;
  // execd's proxy is free to drop a connection it considers idle, and an ssh session can sit
  // silent for hours. A ping costs 6 bytes and keeps every hop's timer alive.
  const ping = setInterval(() => {
    if (!closed) ws.write(encodeFrame(OP_PING, Buffer.alloc(0), true));
  }, 30_000);
  ping.unref();
  const bye = () => {
    if (closed) return;
    closed = true;
    clearInterval(ping);
    client.destroy();
    ws.destroy();
  };
  const onWs = (chunk: Buffer) => {
    let frames;
    try {
      frames = dec.push(chunk);
    } catch {
      return bye(); // a frame that can never be valid — the stream is unusable
    }
    for (const f of frames) {
      if (f.opcode === OP_CLOSE) return bye();
      if (f.opcode === OP_PING) {
        ws.write(encodeFrame(OP_PONG, f.payload, true));
        continue;
      }
      if (f.opcode === OP_PONG) continue;
      // 0x0/0x1/0x2 all carry stream bytes; only their order matters, not the boundaries.
      client.write(f.payload);
    }
    // One drain listener per stall, never one per frame (a chunk can carry many).
    if (client.writableNeedDrain && !ws.isPaused()) {
      ws.pause();
      client.once("drain", () => ws.resume());
    }
  };
  if (head.length) onWs(head);
  ws.on("data", onWs);
  client.on("data", (chunk: Buffer) => {
    ws.write(encodeFrame(OP_BINARY, chunk, true));
    if (ws.writableNeedDrain && !client.isPaused()) {
      client.pause();
      ws.once("drain", () => client.resume());
    }
  });
  for (const s of [client, ws]) {
    s.on("error", bye);
    s.on("close", bye);
    s.on("end", bye);
  }
  client.resume();
}
