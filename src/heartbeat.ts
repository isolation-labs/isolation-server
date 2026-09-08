// Phone-home (contract identical to the isolation daemon's, so the existing cloud
// backend needs no changes): a paired gate periodically reports its CURRENT reachable
// URL + proves liveness. The backend probes that URL inbound (the same path a browser
// takes) and drives the server's liveness dot from the verdict. Daemon→backend only.
import { PORT, getPairing, getVpc, isLoopbackOrigin, savePairing, saveEnrollment, saveBastion, saveSandbox, saveVpc, getMachineId } from "./config.js";
import { GATE_VERSION } from "./version.js";
import { privateTunnelManager, sandboxTunnelManager, tunnelManager } from "./tunnel.js";
import { bastion } from "./bastion.js";

const log = (...a: unknown[]) => console.log("[heartbeat]", ...a);
const INTERVAL_OK_MS = 60_000;
const INTERVAL_WARMUP_MS = 10_000;
// Detaching is destructive (recovery = manual re-pair): only after consecutive
// APP-level rejections, never on a single edge blip.
const DETACH_REJECTS = 3;

export interface BeatStatus {
  ok: boolean;
  at: number;
  status?: number;
  detached?: boolean;
}

let timer: ReturnType<typeof setTimeout> | undefined;
// Which tick chain owns `timer`. stopHeartbeat() bumps it, so a beat that was already in flight
// when the chain was restarted (beatNow, startHeartbeat) retires instead of scheduling a SECOND
// chain — two chains would each keep re-arming, and every further beatNow would double them again.
let chain = 0;
let lastSent: string | undefined;
let lastTunnel: string | undefined;
let lastBeat: BeatStatus | undefined;
let goingOffline = false;
let rejectStreak = 0;

// On a private tunnel there is no public URL to report and no address to choose: the Worker dials
// this server over the binding for its pool slot, and everything behind a tunnel is 127.0.0.1.
// Otherwise (no pool slot — a self-host, a backend with no managed tier) the relay's quick-tunnel URL.
const currentUrl = (): string => {
  if (getVpc()) return `http://127.0.0.1:${PORT}`;
  return tunnelManager.publicUrl() ?? `http://localhost:${PORT}`;
};

// One beat at a time: beatNow() (a quick-tunnel reconnect minting a new URL) can land while a
// scheduled beat is in flight; the follow-up is queued rather than raced, and re-reads the whole
// state anyway — so the LAST beat always carries the current URL, never a stale one landing late.
let inFlight: Promise<void> | undefined;
let queued = false;

function beatSerial(): Promise<void> {
  if (inFlight) {
    queued = true;
    return inFlight;
  }
  inFlight = (async () => {
    try {
      await beat();
    } finally {
      inFlight = undefined;
      if (queued) {
        queued = false;
        await beatSerial();
      }
    }
  })();
  return inFlight;
}

async function beat(): Promise<void> {
  if (goingOffline) return;
  const p = getPairing();
  if (!p) return;
  const url = currentUrl();
  const body: Record<string, unknown> = { connectionId: p.connectionId, secret: p.secret, version: GATE_VERSION, machineId: getMachineId() };
  // Report the URL only when changed — and never report the loopback fallback to a
  // REMOTE cloud (a beat racing the tunnel dial would clobber a still-valid tunnel URL).
  if (url !== lastSent && (isLoopbackOrigin(p.backendUrl) || !isLoopbackOrigin(url))) body.url = url;
  try {
    const r = await fetch(`${p.backendUrl.replace(/\/+$/, "")}/api/pair/heartbeat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) {
      if (typeof body.url === "string") lastSent = body.url;
      rejectStreak = 0;
      lastBeat = { ok: true, at: Date.now() };
      const resp = (await r.json().catch(() => ({}))) as { tunnel?: string; newSecret?: string };
      lastTunnel = resp.tunnel;
      // The cloud auto-rotates the pairing secret over the heartbeat; adopt at once.
      if (typeof resp.newSecret === "string" && resp.newSecret && resp.newSecret !== p.secret) {
        savePairing({ ...p, secret: resp.newSecret });
        log("adopted a rotated pairing secret");
      }
    } else if (r.status === 403 || r.status === 404) {
      // App rejections are JSON; an edge-generated 403/404 is HTML/empty → transient.
      const appVerdict = (r.headers.get("content-type") ?? "").includes("application/json");
      if (appVerdict) rejectStreak++;
      if (appVerdict && rejectStreak >= DETACH_REJECTS) {
        log(`cloud no longer recognizes this server (HTTP ${r.status}, ${rejectStreak} consecutive) — detaching`);
        lastBeat = { ok: false, at: Date.now(), status: r.status, detached: true };
        detach();
      } else {
        lastBeat = { ok: false, at: Date.now(), status: r.status };
        log(`heartbeat rejected (HTTP ${r.status}${appVerdict ? `, strike ${rejectStreak}/${DETACH_REJECTS}` : ", non-app response — ignoring"})`);
      }
    } else {
      lastBeat = { ok: false, at: Date.now(), status: r.status };
      log(`backend rejected heartbeat (HTTP ${r.status})`);
    }
  } catch (e) {
    lastBeat = { ok: false, at: Date.now() };
    log(`heartbeat failed: ${String((e as Error)?.message ?? e)}`);
  }
}

export function detach(): void {
  stopHeartbeat();
  savePairing(undefined);
  saveEnrollment(undefined);
  void tunnelManager.stop();
  // The ssh plane goes with the relay tunnel, for the same reason: both are INBOUND paths the
  // cloud handed us, and a server the cloud no longer recognizes must not keep either one open.
  // Left alone, the bastion connection would go on publishing routes into every live sandbox —
  // still spliceable by anyone on a route's allow-list — using a credential that has been revoked,
  // and the register secret would sit on disk waiting for the next restart to dial back out.
  saveBastion(undefined);
  bastion.disable();
  // Third inbound path, same rule: the public-web (sandbox) tunnel the cloud minted for this
  // server. Left alone it keeps a wildcard hostname resolving to this machine's doorman, so every
  // live view stays reachable from the internet by slug on a credential the cloud has revoked —
  // and the token would sit on disk for the next restart to dial back out. Web views fall back to
  // <slug>.localhost, exactly as they did before this server was ever paired.
  saveSandbox(undefined);
  void sandboxTunnelManager.stop();
  // And the private tunnel: the cloud minted it, the cloud revoked us — it must not keep a way in.
  // (The syncVpcListener call is the config-followed hook, now a no-op — there is no second
  // listener any more; dynamic import because server.ts imports this module.)
  saveVpc(undefined);
  void privateTunnelManager.stop();
  void import("./server.js").then((m) => m.syncVpcListener()).catch(() => undefined);
}

export function pairingStatus(): { paired: boolean; backendUrl?: string; lastBeat?: BeatStatus } {
  const p = getPairing();
  return { paired: !!p, backendUrl: p?.backendUrl, lastBeat };
}

const nextDelay = (): number => (lastTunnel === "connected" ? INTERVAL_OK_MS : INTERVAL_WARMUP_MS);

async function tick(mine: number): Promise<void> {
  await beatSerial();
  if (goingOffline || !getPairing() || mine !== chain) return;
  timer = setTimeout(() => void tick(mine), nextDelay());
}

export function startHeartbeat(): void {
  if (goingOffline) return;
  stopHeartbeat();
  if (!getPairing()) return;
  lastSent = undefined;
  lastBeat = undefined;
  lastTunnel = undefined;
  // Give a just-created tunnel ~10s to serve before the first probe.
  const mine = chain;
  timer = setTimeout(() => void tick(mine), INTERVAL_WARMUP_MS);
}

export function stopHeartbeat(): void {
  if (timer) clearTimeout(timer);
  timer = undefined;
  chain++;
}

export function beatNow(): void {
  if (goingOffline || !getPairing()) return;
  stopHeartbeat();
  void tick(chain);
}

// Final "going offline" beat on graceful shutdown, so the dot flips immediately.
export async function beatOffline(): Promise<void> {
  goingOffline = true;
  stopHeartbeat();
  const p = getPairing();
  if (!p) return;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 3_000);
  try {
    await fetch(`${p.backendUrl.replace(/\/+$/, "")}/api/pair/heartbeat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connectionId: p.connectionId, secret: p.secret, offline: true }),
      signal: ctrl.signal,
    });
  } catch {
    /* best-effort — the heartbeat lapse is the fallback */
  } finally {
    clearTimeout(t);
  }
}
