// The server side of the SSH bastion: one persistent OUTBOUND connection that parks a reverse
// tunnel and registers this server's routes, so an end user types
//
//   ssh <routeId>@ssh.isolation.cc
//
// and never learns a host IP or a port. The bastion terminates their ssh (the username is the only
// routing signal ssh offers — there is no SNI), verifies their public key against the route's
// allow-list, then opens a channel back down THIS connection; we splice it to the session's sshd.
//
// It is a SIBLING of the cloudflared tunnel, not a replacement: that one carries HTTP/WS view bytes
// through Cloudflare, this carries raw SSH through our own box. Both are outbound, so both work
// from behind NAT, and both reconnect on their own.
//
// The bastion's route table is SOFT state — routes live exactly as long as this connection. That is
// deliberate: a route without its tunnel is meaningless. So every (re)connect replays everything,
// and a bastion redeploy costs seconds rather than a registry.
//
// AUTH IS TWO SEPARATE HOPS, and neither of them is us:
//   end user → bastion   the route's allow-list (their public keys, pushed from the launch)
//   bastion → sandbox    a per-connection agent key the bastion mints and pushes to us; we install
//                        the PUBLIC half in each sandbox. The private half never leaves its memory,
//                        it rotates on every reconnect, and it only opens this server's sandboxes.
// The user's own key is never what the container trusts — it is checked at the edge.
import ssh2 from "ssh2";
import { createHash, timingSafeEqual } from "node:crypto";
import type { Duplex } from "node:stream";
import { getBastion, saveBastion, type BastionConfig } from "./config.js";
import { endpointWithHeaders } from "./opensandbox.js";
import { wsConnect } from "./wsframe.js";
import { spliceOverWs } from "./sshfwd.js";
import { SSH_BRIDGE_PORT, SSHD_PORT } from "./launch.js";

const { Client } = ssh2;
const log = (...a: unknown[]) => console.log("[bastion]", ...a);
// A control line is one JSON op; the largest realistic one is a register carrying a route's key
// allow-list. 256 KiB is orders of magnitude past that, and bounds what an unframed peer can grow.
const MAX_CTRL_LINE = 256 * 1024;

export type RouteMode = "tmux" | "shell";

export interface RouteReg {
  routeId: string;
  sessionId: string; // the SANDBOX id: it is what comes back as srcIP on a reverse channel
  viewId: string;
  viewType: string;
  mode: RouteMode; // tmux = attach the view's live tmux session; shell = transparent (VS Code, scp)
  tmuxTarget?: string;
  dir?: string;
  label?: string;
  keys: string[]; // the end-user public keys allowed to open this route
  containerSshPort: number;
}

class BastionClient {
  private settings?: BastionConfig;
  private conn?: ssh2.Client;
  private control?: Duplex;
  private connected = false;
  private stopped = false;
  private reconnectTimer?: NodeJS.Timeout;
  private backoff = 1000;
  private ctrlBuf = "";
  private readonly routes = new Map<string, RouteReg>();
  // The agent PUBLIC key the bastion minted for this connection. Rotates on reconnect, which is why
  // sandboxes get it written to a file of its own that can be rewritten without touching user keys.
  private agentKey?: string;
  private onAgentKey?: (publicKey: string) => void;

  /** Called with each new agent public key so the launch layer can install it in live sandboxes. */
  onAgentKeyRotated(fn: (publicKey: string) => void): void {
    this.onAgentKey = fn;
  }

  enabled(): boolean {
    return !!this.settings;
  }
  isLive(): boolean {
    return this.connected;
  }
  agentPublicKey(): string | undefined {
    return this.agentKey;
  }
  publicHost(): string | undefined {
    return this.settings?.publicHost;
  }
  edgePort(): number | undefined {
    return this.settings?.edgePort;
  }

  /**
   * Read the config and dial. The single entry point for boot, pairing and `POST /bastion`.
   *
   * Idempotent for an UNCHANGED config, but a changed one must redial: the live connection is what
   * holds our routes, so silently keeping it would leave this server registered with the previous
   * bastion while reporting the new one — every `ssh <routeId>@<new host>` then answers "permission
   * denied", because the route it is looking for lives somewhere else entirely.
   */
  startIfConfigured(): void {
    const cfg = getBastion();
    if (!cfg) return;
    const changed = this.settings && !sameEndpoint(this.settings, cfg);
    this.settings = cfg;
    this.stopped = false;
    if (changed && this.conn) {
      log(`bastion changed → ${cfg.controlHost}:${cfg.controlPort}; reconnecting`);
      const old = this.conn;
      this.conn = undefined; // so the close handler doesn't schedule a reconnect to the old one
      this.connected = false;
      this.control = undefined;
      try {
        old.end();
      } catch {
        /* already gone */
      }
    }
    if (!this.conn) this.dial();
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.reconnectTimer);
    try {
      this.conn?.end();
    } catch {
      /* already gone */
    }
  }

  /**
   * The cloud says this server has no bastion any more. Drop the connection AND the local state:
   * leaving `settings` behind would keep `/status` reporting a configured ssh plane, and leaving
   * the routes behind would replay them at whatever bastion is configured next.
   */
  disable(): void {
    this.stop();
    this.settings = undefined;
    this.routes.clear();
    this.agentKey = undefined;
  }

  private dial(): void {
    const s = this.settings;
    if (!s) return;
    // A retry may already be armed (a redial on a config change, say). Letting it fire on top of
    // this connection would leave two control connections racing to own the same route table.
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    const c = new Client();
    this.conn = c;
    // EVERY handler below ignores a connection that is no longer the live one. `startIfConfigured`
    // swaps the client out on a config change, and the old client's 'close' lands AFTER the new one
    // is in place: unguarded, it would null out the live connection's state and schedule a
    // reconnect on top of it — two connections, and a route table nobody is replaying into.
    const mine = () => this.conn === c;
    c.on("ready", () => {
      if (!mine()) return;
      this.onReady(c); // the backoff resets only once the control channel is actually open
    });
    // The bastion opening a channel back to us: one end user's ssh session.
    c.on("tcp connection", (info, accept, reject) => {
      if (!mine()) return void reject(); // a superseded connection has no sandboxes to offer
      this.onReverseChannel(info, accept);
    });
    c.on("error", (e: Error) => {
      if (mine()) log(`connection error: ${e?.message ?? e}`);
    });
    c.on("close", () => {
      if (!mine()) return;
      this.connected = false;
      this.control = undefined;
      this.conn = undefined;
      if (!this.stopped) this.scheduleReconnect();
    });
    try {
      c.connect({
        host: s.controlHost,
        port: s.controlPort,
        // The control credential is per-connection: username = our connectionId, password =
        // HMAC(the cloud's signing key, that id). A leaked one can register only our routes.
        username: s.daemonLabel,
        password: s.registerSecret,
        // ssh2 accepts ANY host key when no verifier is given, and this connection is the one that
        // presents our register credential AND is trusted to push an agent public key we install
        // in every sandbox — so an on-path impostor of the bastion would own every session on this
        // server. Pin it instead (see verifyHostKey).
        hostVerifier: (key: Buffer) => this.verifyHostKey(c, key),
        keepaliveInterval: 20_000,
        readyTimeout: 15_000,
      });
    } catch (e) {
      log(`connect threw: ${(e as Error)?.message ?? e}`);
      if (mine()) {
        this.conn = undefined;
        this.scheduleReconnect();
      }
    }
  }

  /**
   * Trust-on-first-use pinning of the bastion's host key, upgraded to a hard pin the moment the
   * cloud hands one down (`hostKey` in the coords, fetched over HTTPS). Without this, anyone on the
   * path — a hijacked DNS answer for the control host is enough — can impersonate the bastion,
   * collect our register credential, push their own agent public key (which we then install in
   * every live sandbox) and ssh into all of them. A mismatch is fatal for the dial, never papered
   * over: the reconnect loop retries, and the log says exactly what happened.
   */
  private verifyHostKey(c: ssh2.Client, key: Buffer): boolean {
    if (this.conn !== c) return false; // a superseded dial has nothing left to pin for
    const s = this.settings;
    if (!s) return false; // disabled mid-handshake
    const offered = Buffer.from(key);
    if (s.hostKey) {
      const pinned = Buffer.from(s.hostKey, "base64");
      const ok = pinned.length === offered.length && timingSafeEqual(pinned, offered);
      if (!ok) {
        log(`REFUSED ${s.controlHost}: host key ${fingerprint(offered)} does not match the pinned one. Either something is impersonating the bastion, or its key was rotated — re-pair this server to accept a new one.`);
      }
      return ok;
    }
    s.hostKey = offered.toString("base64");
    saveBastion(s);
    log(`pinned the bastion host key on first connect (${fingerprint(offered)})`);
    return true;
  }

  /**
   * A connection that is up at the TCP/SSH layer but useless above it — no reverse tunnel, or no
   * control channel — must be TORN DOWN, not merely noted.
   *
   * ssh2's keepalive holds such a connection open indefinitely, and `startIfConfigured` refuses to
   * dial while `this.conn` is set, so anything that only flipped `connected` to false would leave
   * this server permanently ssh-dark: routes queued in the map and never replayed, `send()` a
   * silent no-op, and nothing left that ever retries. Ending it lets the 'close' handler run the
   * ordinary reconnect loop, which is the one path that recovers.
   */
  private redial(c: ssh2.Client, why: string): void {
    if (this.conn !== c) return; // a superseded connection is already someone else's problem
    log(`${why} — dropping the connection so the reconnect loop can retry`);
    try {
      c.end();
    } catch {
      /* already gone; the 'close' handler still fires */
    }
  }

  private onReady(c: ssh2.Client): void {
    // Park the reverse tunnel — this is what lets the bastion open channels back to us at all.
    // The bastion answers with a VIRTUAL port and keys its forwarding table on it; without this
    // the edge has no way back to us and every session dies with "daemon offline".
    c.forwardIn("127.0.0.1", 0, (e, port) => {
      if (e) this.redial(c, `forwardIn failed — no session could reach this server (${e.message})`);
      else log(`reverse tunnel parked (bound port ${port})`);
    });
    c.exec("iso-control", (err, stream) => {
      if (err) return this.redial(c, `control channel failed (${err.message})`);
      // The exec is a round trip: this connection can have been replaced (or stopped) meanwhile,
      // and adopting its channel would point `this.control` at a client nobody else knows about.
      if (this.conn !== c) return void stream.close();
      this.control = stream;
      this.connected = true;
      this.ctrlBuf = "";
      // Only a WORKING control channel counts as a good connection. Resetting the backoff on
      // 'ready' alone would turn a bastion that authenticates but never accepts `iso-control` into
      // a one-second reconnect loop against a public host.
      this.backoff = 1000;
      stream.on("data", (d: Buffer) => this.onControlData(d));
      stream.on("close", () => {
        if (this.conn !== c) return;
        this.connected = false;
        this.control = undefined;
        // The bastion only logs a closed control channel; it does not drop the connection. So this
        // is the common way to end up connected-but-unregistered, and the redial is what fixes it.
        this.redial(c, "the bastion closed the control channel");
      });
      for (const r of this.routes.values()) this.send({ op: "register", ...r });
      // `settings` can be gone by now (a `disable()` that raced this round trip); an exception
      // raised inside an ssh2 callback has nothing above it to catch and would end the process.
      log(`connected to ${this.settings?.controlHost ?? "the bastion"} — ${this.routes.size} route(s) replayed`);
    });
  }

  // The bastion wants a stream to a sandbox's sshd: it puts the sandbox id in srcIP and the
  // in-container port in srcPort. Everything past that is the same splice `ssh -p` uses — the WS
  // bridge is the only transport into a sandbox either way (see sshfwd.ts).
  private onReverseChannel(info: { srcIP?: string; srcPort?: number }, accept: () => Duplex): void {
    const sandboxId = info?.srcIP ?? "";
    log(`session in → sandbox ${sandboxId.slice(0, 8) || "?"}:${info?.srcPort ?? "?"}`);
    const ch = accept() as Duplex & { close?: () => void };
    // The channel has no 'error' handler of its own; an unhandled one would take the process down.
    // close(), never destroy(): a channel that disappears without its protocol close makes the
    // bastion reset the CONTROL connection, taking every one of this server's routes with it.
    const drop = () => {
      try {
        // NOT `ch.close?.() ?? ch.destroy()` — close() returns undefined, so `??` would run the
        // destroy as well and undo the whole point of closing politely.
        if (typeof ch.close === "function") ch.close();
        else ch.destroy();
      } catch {
        /* already gone */
      }
    };
    ch.on("error", drop);
    // The bastion NAMES the sandbox it wants, and that name goes straight into a runtime API path.
    // Honor it only for a sandbox we ourselves published a route for: an unregistered id (a stale
    // route, a confused edge, a crafted one carrying `../`) must never reach the runtime, which
    // answers on loopback with our API key and knows every sandbox on this host.
    if (!sandboxId || !this.hasSandbox(sandboxId)) {
      if (sandboxId) log(`refused a channel for an unregistered sandbox`);
      return drop();
    }
    ch.pause();
    endpointWithHeaders(sandboxId, SSH_BRIDGE_PORT)
      .then(({ host, basePath, headers }) => wsConnect({ host, path: `${basePath}/`, headers }))
      .then(({ socket, head }) => {
        log(`session spliced → sandbox ${sandboxId.slice(0, 8)}`);
        spliceOverWs(ch, socket, head);
      })
      .catch((e: Error) => {
        log(`no route into ${sandboxId.slice(0, 8)}: ${e?.message ?? e}`);
        drop();
      });
  }

  private onControlData(d: Buffer): void {
    this.ctrlBuf += d.toString("utf8");
    let nl: number;
    while ((nl = this.ctrlBuf.indexOf("\n")) >= 0) {
      const line = this.ctrlBuf.slice(0, nl).trim();
      this.ctrlBuf = this.ctrlBuf.slice(nl + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as { op?: string; publicKey?: string };
        if (msg?.op === "agentkey" && typeof msg.publicKey === "string" && msg.publicKey.startsWith("ssh-")) {
          const key = msg.publicKey.trim();
          if (key !== this.agentKey) {
            this.agentKey = key;
            this.onAgentKey?.(key);
          }
        }
      } catch {
        /* a malformed ack is the bastion's problem, never ours */
      }
    }
    // What is left is one PARTIAL line. The control channel is line-delimited JSON from a remote
    // peer, so a peer that never sends a newline (a bug, or a bastion someone else has taken over)
    // would grow this string without limit until the process dies. No legitimate op comes close to
    // the cap, so an oversized fragment is garbage: drop it and resynchronize on the next newline.
    if (this.ctrlBuf.length > MAX_CTRL_LINE) {
      // The tail of the dropped line still arrives and parses as invalid JSON — which the loop
      // above already swallows — so there is nothing further to suppress.
      log(`control line over ${MAX_CTRL_LINE} bytes — discarding it`);
      this.ctrlBuf = "";
    }
  }

  private send(o: Record<string, unknown>): void {
    if (!this.control || !this.connected) return; // queued in `routes`; replayed on reconnect
    try {
      this.control.write(`${JSON.stringify(o)}\n`);
    } catch (e) {
      log(`send failed: ${(e as Error)?.message ?? e}`);
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    clearTimeout(this.reconnectTimer);
    const delay = this.backoff;
    this.backoff = Math.min(this.backoff * 2, 30_000);
    this.reconnectTimer = setTimeout(() => this.dial(), delay);
    this.reconnectTimer.unref();
  }

  // --- routes (idempotent; the map is what a reconnect replays) ---------------------------------

  registerRoute(r: RouteReg): void {
    this.routes.set(r.routeId, r);
    this.send({ op: "register", ...r });
  }
  unregisterRoute(routeId: string): void {
    if (this.routes.delete(routeId)) this.send({ op: "unregister", routeId });
  }
  /** Do we currently publish a route into this sandbox? The gate on every inbound channel. */
  private hasSandbox(sandboxId: string): boolean {
    for (const r of this.routes.values()) if (r.sessionId === sandboxId) return true;
    return false;
  }
  unregisterSandbox(sandboxId: string): void {
    for (const [id, r] of this.routes) if (r.sessionId === sandboxId) this.unregisterRoute(id);
  }
  /** Replace the end-user keys on every route of a sandbox (a live grant, or a re-launch). */
  setSandboxKeys(sandboxId: string, keys: string[]): void {
    for (const r of this.routes.values()) {
      if (r.sessionId !== sandboxId) continue;
      r.keys = keys;
      this.send({ op: "setkeys", routeId: r.routeId, keys });
    }
  }
  routeCount(): number {
    return this.routes.size;
  }
}

// OpenSSH's own fingerprint shape, so an operator can compare it against `ssh-keyscan` output.
function fingerprint(key: Buffer): string {
  return `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
}

// Same bastion, same credential? Only these decide whether a live connection can be kept.
function sameEndpoint(a: BastionConfig, b: BastionConfig): boolean {
  return a.controlHost === b.controlHost && a.controlPort === b.controlPort && a.daemonLabel === b.daemonLabel && a.registerSecret === b.registerSecret;
}

export const bastion = new BastionClient();

// Which view types are reachable over ssh, and how.
//
// TERMINAL ONLY, deliberately. A terminal route attaches the very tmux session the browser shows,
// so the two are one live screen — that is a feature you can explain in a sentence. The other types
// would each be a plain shell wearing a different label, which is a worse thing to ship than
// nothing: `code` promises VS Code Remote (its own setup story) and `directory` promises files
// (which means SMB, not ssh). Neither is decided, so neither gets an address.
export function modeForView(type: string): RouteMode | undefined {
  return type === "terminal" ? "tmux" : undefined;
}

/** `ssh <routeId>@<host>` for a view, when the bastion is configured and the type is reachable. */
export function sshCommandFor(routeId: string): string | undefined {
  const host = bastion.publicHost();
  if (!host) return undefined;
  const port = bastion.edgePort() ?? 22;
  return `ssh ${routeId}@${host}${port === 22 ? "" : ` -p ${port}`}`;
}

/**
 * Everything the web needs to open this route in a real terminal (the daemon's `nativeConnect`
 * contract). Passwordless by construction: the member's key was checked at the edge, so there is
 * no credential to hand out here and nothing secret in this payload.
 */
export function nativeConnectFor(routeId: string, sessionId: string, viewId: string): Record<string, unknown> | undefined {
  const host = bastion.publicHost();
  const command = sshCommandFor(routeId);
  if (!host || !command) return undefined;
  const port = bastion.edgePort() ?? 22;
  return {
    kind: "terminal",
    host,
    port,
    user: routeId,
    routeId,
    sessionId,
    viewId,
    passwordless: true,
    bastion: true,
    command,
    // `ssh://` is what makes it one click: the OS hands it to the default terminal.
    sshUrl: `ssh://${routeId}@${host}${port === 22 ? "" : `:${port}`}`,
  };
}

export const CONTAINER_SSH_PORT = SSHD_PORT;
