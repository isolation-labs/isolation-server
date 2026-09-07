// Phone-home (contract identical to the isolation daemon's, so the existing cloud
// backend needs no changes): a paired gate periodically reports its CURRENT reachable
// URL + proves liveness. The backend probes that URL inbound (the same path a browser
// takes) and drives the server's liveness dot from the verdict. Daemon→backend only.
import { PORT, getPairing, getVpc, isLoopbackOrigin, savePairing, saveEnrollment, saveBastion, saveSandbox, saveVpc, getMachineId } from "./config.js";
import { GATE_VERSION } from "./version.js";
import { privateTunnelManager, sandboxTunnelManager, tunnelManager } from "./tunnel.js";
import { allWebSlugs } from "./views.js";
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
let lastSent: string | undefined;
let lastTunnel: string | undefined;
let lastBeat: BeatStatus | undefined;
let goingOffline = false;
let rejectStreak = 0;

// On a private tunnel (docs/vpc-plan.md) the server's address IS its loopback ip — the Worker dials
// it over the binding — and there is no public URL to report. Otherwise the relay's quick-tunnel URL.
const currentUrl = (): string => {
  const v = getVpc();
  if (v) return `http://${v.ip}:${PORT}`;
  return tunnelManager.publicUrl() ?? `http://localhost:${PORT}`;
};

async function beat(): Promise<void> {
  if (goingOffline) return;
  const p = getPairing();
  if (!p) return;
  const url = currentUrl();
  const body: Record<string, unknown> = { connectionId: p.connectionId, secret: p.secret, version: GATE_VERSION, machineId: getMachineId() };
  // Public web previews (docs/vpc-plan.md): every live web view's slug, so the Worker can route
  // https://<slug>.<domain>/ to this server. The cloud replaces its list per beat.
  body.webSlugs = allWebSlugs();
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
  saveVpc(undefined);
  void privateTunnelManager.stop();
}

export function pairingStatus(): { paired: boolean; backendUrl?: string; lastBeat?: BeatStatus } {
  const p = getPairing();
  return { paired: !!p, backendUrl: p?.backendUrl, lastBeat };
}

const nextDelay = (): number => (lastTunnel === "connected" ? INTERVAL_OK_MS : INTERVAL_WARMUP_MS);

async function tick(): Promise<void> {
  await beat();
  if (goingOffline || !getPairing()) return;
  timer = setTimeout(() => void tick(), nextDelay());
}

export function startHeartbeat(): void {
  if (goingOffline) return;
  stopHeartbeat();
  if (!getPairing()) return;
  lastSent = undefined;
  lastBeat = undefined;
  lastTunnel = undefined;
  // Give a just-created tunnel ~10s to serve before the first probe.
  timer = setTimeout(() => void tick(), INTERVAL_WARMUP_MS);
}

export function stopHeartbeat(): void {
  if (timer) clearTimeout(timer);
  timer = undefined;
}

export function beatNow(): void {
  if (goingOffline || !getPairing()) return;
  stopHeartbeat();
  void tick();
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
