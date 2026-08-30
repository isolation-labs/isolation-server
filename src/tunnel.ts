// The relay tunnel — a free cloudflared quick tunnel fronting the doorman. Provider
// stays behind this interface (the enrollment names it); the URL is never hardcoded
// and changes on every restart, which the heartbeat self-heals.
import { type ChildProcess, spawn } from "node:child_process";
import { HOST, PORT, getSandbox } from "./config.js";

const log = (...a: unknown[]) => console.log("[tunnel]", ...a);

const URL_RE = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/;
const RESTART_BACKOFF_MS = [2_000, 5_000, 15_000, 60_000];

import { ensureCloudflared } from "./cloudflared.js";

export interface TunnelStatus {
  connected: boolean;
  url?: string;
}

class TunnelManager {
  private child: ChildProcess | undefined;
  private url: string | undefined;
  private stopping = false;
  private restarts = 0;
  lastError: string | undefined;
  // Fired when the public URL changes (a reconnect minted a fresh one) — the
  // heartbeat hooks this to report the new address immediately.
  onUrlChange: ((url: string) => void) | undefined;

  publicUrl(): string | undefined {
    return this.url;
  }

  status(): TunnelStatus {
    return { connected: !!this.url && !!this.child, url: this.url };
  }

  // Bring the tunnel up and resolve once it has a public URL (or reject on timeout).
  async start(): Promise<string> {
    if (this.url && this.child) return this.url;
    this.stopping = false;
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(this.lastError ?? "tunnel did not produce a URL in time")), 30_000);
      this.spawnOnce((u) => {
        clearTimeout(timer);
        resolve(u);
      });
    });
  }

  private spawnOnce(onFirstUrl?: (u: string) => void): void {
    void ensureCloudflared(log)
      .then((bin) => this.spawnWith(bin, onFirstUrl))
      .catch((e: Error) => {
        this.lastError = e.message;
        log(e.message);
      });
  }

  private spawnWith(bin: string, onFirstUrl?: (u: string) => void): void {
    const child = spawn(bin, ["tunnel", "--url", `http://${HOST}:${PORT}`], { stdio: ["ignore", "pipe", "pipe"] });
    this.child = child;
    let announced = false;
    const scan = (chunk: Buffer) => {
      const m = URL_RE.exec(chunk.toString());
      if (m && !announced) {
        announced = true;
        const fresh = m[0];
        const changed = this.url !== undefined && this.url !== fresh;
        this.url = fresh;
        this.restarts = 0;
        log(`up: ${fresh}`);
        onFirstUrl?.(fresh);
        if (changed) this.onUrlChange?.(fresh);
      }
    };
    child.stdout?.on("data", scan);
    child.stderr?.on("data", scan);
    child.on("error", (e) => {
      this.lastError = e.message;
      log(`spawn failed: ${e.message}`);
    });
    child.on("exit", (code) => {
      this.child = undefined;
      this.url = undefined;
      if (this.stopping) return;
      const delay = RESTART_BACKOFF_MS[Math.min(this.restarts++, RESTART_BACKOFF_MS.length - 1)];
      log(`exited (code ${code}) — restarting in ${delay / 1000}s`);
      setTimeout(() => {
        if (!this.stopping) this.spawnOnce();
      }, delay);
    });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.url = undefined;
    const c = this.child;
    this.child = undefined;
    if (!c) return;
    c.kill("SIGTERM");
    await new Promise<void>((r) => {
      const t = setTimeout(() => {
        c.kill("SIGKILL");
        r();
      }, 3_000);
      c.on("exit", () => {
        clearTimeout(t);
        r();
      });
    });
  }
}

export const tunnelManager = new TunnelManager();

// The sandbox (public web) tunnel: a NAMED cloudflared tunnel whose ingress the cloud
// configured as `*.<domain>` → http://localhost:<PORT>. We only run it with its token.
class SandboxTunnelManager {
  private child: ChildProcess | undefined;
  private stopping = false;
  private up = false;

  status(): { connected: boolean; domain?: string } {
    return { connected: this.up, domain: getSandbox()?.domain };
  }

  async start(): Promise<void> {
    await this.stop();
    const sb = getSandbox();
    if (!sb) return;
    if (sb.provider !== "cloudflared") throw new Error(`unsupported sandbox provider '${sb.provider}'`);
    const bin = await ensureCloudflared(log);
    this.stopping = false;
    const child = spawn(bin, ["tunnel", "run", "--token", sb.creds], { stdio: ["ignore", "pipe", "pipe"] });
    this.child = child;
    const scan = (chunk: Buffer) => {
      if (!this.up && /Registered tunnel connection/i.test(chunk.toString())) {
        this.up = true;
        log(`sandbox relay connected → *.${sb.domain}`);
      }
    };
    child.stdout?.on("data", scan);
    child.stderr?.on("data", scan);
    child.on("exit", (code) => {
      this.child = undefined;
      this.up = false;
      if (this.stopping) return;
      log(`sandbox tunnel exited (code ${code}) — restarting in 5s`);
      setTimeout(() => {
        if (!this.stopping) void this.start().catch((e: Error) => log(e.message));
      }, 5_000);
    });
  }

  async stop(): Promise<void> {
    this.stopping = true;
    this.up = false;
    const c = this.child;
    this.child = undefined;
    if (!c) return;
    c.kill("SIGTERM");
    await new Promise<void>((r) => {
      const t = setTimeout(() => {
        c.kill("SIGKILL");
        r();
      }, 3_000);
      c.on("exit", () => {
        clearTimeout(t);
        r();
      });
    });
  }
}

export const sandboxTunnelManager = new SandboxTunnelManager();
