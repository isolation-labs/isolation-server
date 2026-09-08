// The isolation-server HTTP surface — control plane (loopback + tunnel, master-token-gated)
// plus the /v/* data plane (view-token-gated, handled by the doorman). Plain
// node:http: the doorman needs the raw 'upgrade' event anyway, and the API surface
// is small enough that a framework would outweigh it.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { GATE_VERSION } from "./version.js";
import { HOST, PORT, getBastion, getName, getPairing, getToken, getVpc, isLoopbackOrigin, originAllowed, saveBastion, savePairing, saveVpc, tokenMatches, getMachineId } from "./config.js";
import { beatNow, beatOffline, detach, pairingStatus, startHeartbeat } from "./heartbeat.js";
import { deleteSandbox, getSandbox, listSandboxes, osbHealthy, pauseSandbox, resumeSandbox, sandboxLogs } from "./opensandbox.js";
import { handlePublicWebRequest, handlePublicWebUpgrade, handleViewRequest, handleViewUpgrade, invalidateEndpoints } from "./doorman.js";
import { launch, restartTerminal, sanitizeStyle, type LaunchRequest } from "./launch.js";
import { sinkFor, abortMerge, dropSink, saveWorkspace, syncWorkspace } from "./persistence.js";
import { dropView, dropViewsForSandbox, ensureRouteId, getView, mintViewToken, updateView, viewsForSandbox, type View } from "./views.js";
import { forgetExecd, run } from "./execd.js";
import { agentJson, getAgent, listAgents, parseRoster, spawnAgent, startAgent, stopAgent } from "./agents.js";
import { bridgePattern, connectorTurn, syncViewsFile } from "./acpview.js";
import { listHarnesses } from "./harness.js";
import { pauseSession, resumeSession,
  createSessionView,
  dropSshForSandbox,
  finishSession,
  getSessionRecord,
  listSessionRecords,
  renameSession,
  sessionChanges,
  sessionJson,
  sessionViews,
  sshKeysFor,
  syncRoutes,
  startSession,
  viewJson,
  type DaemonLaunchBody,
} from "./sessions.js";
import { privateTunnelManager, sandboxTunnelManager, tunnelManager } from "./tunnel.js";
import { bastion, modeForView, nativeConnectFor } from "./bastion.js";

const VERSION = GATE_VERSION;
const log = (...a: unknown[]) => console.log("[isolation-server]", ...a);

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// Ask the cloud for the SSH bastion coords (POST /api/pair/bastion, authed by the per-connection
// pairing secret) and store them, then dial. The credential it returns is per-connection —
// HMAC(the cloud's signing key, our connectionId) — so it can only ever register OUR routes.
async function fetchBastionConfig(backendUrl: string, connectionId: string, secret: string): Promise<void> {
  try {
    const r = await fetch(`${backendUrl}/api/pair/bastion`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connectionId, secret }),
    });
    const body = (await r.json().catch(() => ({}))) as { bastion?: Record<string, unknown> | null };
    const b = body.bastion;
    // A transient failure is NOT an answer: a 502 from the backend (or a deploy window) must never
    // wipe coords that work, or the ssh plane would go dark until someone re-paired the server.
    // Only a healthy backend saying "no bastion" tears it down.
    if (!r.ok) return log(`bastion config fetch: HTTP ${r.status} — keeping the current coords`);
    if (!b || typeof b.controlHost !== "string" || typeof b.registerSecret !== "string") {
      if (getBastion()) log("the cloud reports no ssh bastion for this server — falling back to the local forwarder");
      saveBastion(undefined);
      bastion.disable();
      return;
    }
    const controlPort = Number(b.controlPort ?? 2200);
    // The pinned host key survives a coords refresh: the cloud does not (yet) serve one, so
    // dropping it here would silently re-TOFU on the very next dial and reopen the window the pin
    // exists to close. A key served by the cloud always wins; a MOVED bastion starts over.
    const prev = getBastion();
    const carried = prev?.controlHost === b.controlHost && prev?.controlPort === controlPort ? prev.hostKey : undefined;
    const hostKey = typeof b.hostKey === "string" && b.hostKey ? b.hostKey : carried;
    saveBastion({
      controlHost: b.controlHost,
      controlPort,
      publicHost: typeof b.publicHost === "string" ? b.publicHost : b.controlHost,
      edgePort: Number(b.edgePort ?? 22),
      daemonLabel: typeof b.daemonLabel === "string" ? b.daemonLabel : connectionId,
      ...(typeof b.smbHost === "string" ? { smbHost: b.smbHost } : {}),
      registerSecret: b.registerSecret,
      ...(hostKey ? { hostKey } : {}),
    });
    bastion.startIfConfigured();
    log(`ssh bastion configured — users reach sessions at ${bastion.publicHost()}`);
  } catch (e) {
    log(`bastion config fetch failed (staying local-only): ${(e as Error)?.message ?? e}`);
  }
}

const bearer = (req: IncomingMessage): string | undefined => {
  const a = req.headers.authorization;
  return a?.startsWith("Bearer ") ? a.slice(7) : undefined;
};

// SSRF guard for the pairing backend URL (defense-in-depth; /pair is token-gated):
// refuse non-http(s) and link-local / cloud-metadata targets. LAN + loopback allowed.
function backendUrlSafe(u: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(u);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return !/^169\.254\./.test(host) && host !== "metadata.google.internal" && host !== "fd00:ec2::254";
}

// Bring up whatever the config prescribes: tunnel when enrolled, heartbeat when
// paired. Idempotent — the boot path and the pair path share it.
import { getEnrollment, getSandbox as getSandboxConfig, saveEnrollment, saveSandbox } from "./config.js";
export async function startConfigured(opts?: { forceRelay?: boolean }): Promise<void> {
  // A server on a private tunnel has NO public surface: the relay quick tunnel is not started at
  // boot. Pairing still brings one up briefly — the claim needs a reachable URL — and
  // fetchVpcConfig stops it the moment the private tunnel is configured. `forceRelay` is the pair
  // path saying so: a RE-pair runs with the PREVIOUS pairing's vpc block still on disk, and
  // suppressing the relay on that stale block would fail the claim ("could not establish a relay
  // tunnel") on every server that has ever had a private tunnel.
  if (getEnrollment() && (opts?.forceRelay || !getVpc()) && !tunnelManager.status().connected) {
    try {
      await tunnelManager.start();
    } catch (e) {
      log(`tunnel bring-up failed: ${String((e as Error)?.message ?? e)}`);
    }
  }
  if (getPairing()) startHeartbeat();
  if (getSandboxConfig()?.creds && !sandboxTunnelManager.status().connected) {
    await sandboxTunnelManager.start().catch((e: Error) => log(`sandbox tunnel bring-up failed: ${e.message}`));
  }
  // The SSH bastion: an outbound control connection that publishes `ssh <routeId>@<host>` for every
  // ssh-shaped view. A server with no bastion config just stays on the local forwarder.
  bastion.startIfConfigured();
  // The private tunnel: the cloud's only way in. Bind the ip first so the first
  // request the Worker sends after "Registered tunnel connection" has something to land on.
  if (getVpc()) {
    syncVpcListener();
    await privateTunnelManager.start().catch((e: Error) => log(`private tunnel bring-up failed: ${e.message}`));
  }
}

// The cloud injects the public-web (sandbox) tunnel — at provision on a Cloud VM, or
// inline on a launch / via POST /sandbox. Persist + dial; a repeat of the current
// config is a no-op.
function applyInjectedSandbox(s: unknown): void {
  if (!s || typeof s !== "object") return;
  const o = s as Record<string, unknown>;
  const domain = typeof o.domain === "string" ? o.domain.trim().toLowerCase() : "";
  const creds = typeof o.creds === "string" ? o.creds.trim() : "";
  if (!domain) return;
  const cur = getSandboxConfig();
  if (cur && cur.domain === domain && (cur.creds ?? "") === creds) return;
  // Domain only: web views are https://<slug>.<domain>/ and the Worker delivers
  // them over the private tunnel — nothing to dial here. Creds = the legacy per-server public wildcard.
  saveSandbox(creds ? { provider: "cloudflared", creds, domain } : { domain });
  if (creds) void sandboxTunnelManager.start().catch((e: Error) => log(`sandbox tunnel (injected) failed: ${e.message}`));
  // Migrating off the legacy wildcard: the creds are gone from disk, so the running cloudflared
  // must go too — an inbound path the cloud has replaced may not stay dialed on a stale token.
  else void sandboxTunnelManager.stop();
}

// A usable private address: a real 127.x.y.z with in-range octets, and never 127.0.0.1 — that one
// is the MAIN listener's, so binding it would fail with EADDRINUSE forever while the relay has
// already been torn down, leaving no way back in. Anything else is a backend bug: refuse it here so
// the vpc block we already hold is kept (see below) instead of being replaced by an address we can
// never serve.
function privateIp(ip: string): boolean {
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  return !!m && m.slice(1).every((o) => Number(o) <= 255) && ip !== "127.0.0.1";
}

// The server's PRIVATE tunnel + address (POST /api/pair/vpc — same auth as the bastion coords).
// The cloud mints it once and returns the same pair after; we run the tunnel and bind on the ip.
// A backend with no managed tier answers `{vpc: null}` and this server stays loopback-only.
async function fetchVpcConfig(backendUrl: string, connectionId: string, secret: string): Promise<void> {
  try {
    const r = await fetch(`${backendUrl}/api/pair/vpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connectionId, secret }),
    });
    type VpcAnswer = { vpc?: { creds?: string; ip?: string; domain?: string } | null };
    // `undefined` = the answer was not JSON at all. That is NOT the cloud speaking, so it must never
    // revoke: an HTML interstitial or a truncated 200 in front of the backend would otherwise cost
    // this server its only way in, and nothing re-fetches on its own afterwards — the cloud would go
    // on dialing a private ip we no longer serve until someone ran `POST /vpc` by hand.
    const body = (await r.json().catch(() => undefined)) as VpcAnswer | undefined;
    if (!r.ok) return log(`vpc config fetch: HTTP ${r.status} — keeping the current one`);
    if (!body || typeof body !== "object") return log("vpc config fetch: the answer was not JSON — keeping the current one");
    const v = body.vpc;
    const creds = typeof v?.creds === "string" && v.creds ? v.creds : undefined;
    const ip = typeof v?.ip === "string" && privateIp(v.ip) ? v.ip : undefined;
    if (!creds || !ip) {
      // A well-formed answer carrying a MALFORMED block is a backend bug, not a revocation either —
      // only an explicit `{vpc: null}` is the cloud saying this server has no private tunnel.
      if (v) return log("vpc config fetch: malformed vpc block — keeping the current one");
      // A HEALTHY backend saying "no private tunnel" revokes the one we hold — same rule as the
      // bastion coords, and unlike the sandbox config the vpc block has no self-hoster provenance:
      // only the cloud ever mints it. Left alone it would keep an inbound path open for a cloud (or
      // an account) that no longer owns this server — this is exactly the re-pair-elsewhere case —
      // and `currentUrl()` would go on reporting an ip the new cloud can never dial.
      if (!getVpc()) return;
      log("the cloud reports no private tunnel for this server — dropping the one we hold");
      saveVpc(undefined);
      await privateTunnelManager.stop();
      syncVpcListener();
      // With the private tunnel gone the relay is the only way back in; startConfigured is
      // idempotent and now sees no vpc block, so it brings one up when this server is enrolled.
      await startConfigured().catch((e: Error) => log(`relay bring-up after vpc revocation failed: ${e.message}`));
      return;
    }
    // The preview domain: web views become https://<slug>.<domain>/, served by the Worker over this
    // very tunnel. Domain only — no creds, nothing to dial (see applyInjectedSandbox).
    // The cloud is AUTHORITATIVE for the preview domain: no domain in the answer means this
    // deployment does not serve one (a loopback backend), so a previously-set domain-only config is
    // CLEARED rather than left behind — otherwise every web view would go on advertising a URL that
    // resolves to someone else's Worker. A creds-bearing (legacy public wildcard) config is left
    // alone; that one is not ours to drop here.
    if (typeof v?.domain === "string" && v.domain) applyInjectedSandbox({ domain: v.domain });
    else if (getSandboxConfig() && !getSandboxConfig()?.creds) {
      log("the cloud serves no preview domain here — web views fall back to <slug>.localhost");
      saveSandbox(undefined);
    }
    const cur = getVpc();
    const unchanged = cur?.creds === creds && cur?.ip === ip;
    // Unchanged coords still re-run the bring-up: POST /vpc is the repair path a user reaches for
    // after fixing a failed bind (the missing lo0 alias), and both steps below are idempotent.
    if (!unchanged) saveVpc({ creds, ip });
    if (!unchanged) await privateTunnelManager.stop();
    // Bind first, dial second — the first request the Worker sends after "Registered tunnel
    // connection" has to land on something (same order as startConfigured).
    syncVpcListener();
    await privateTunnelManager.start().catch((e: Error) => log(`private tunnel failed: ${e.message}`));
    // The public quick tunnel has no job left: everything reaches this server through the Worker.
    if (!isLoopbackOrigin(backendUrl)) void tunnelManager.stop();
    if (unchanged) return;
    log(`private tunnel configured — the cloud reaches this server at ${ip}:${PORT}`);
  } catch (e) {
    log(`vpc config fetch failed: ${(e as Error)?.message ?? e}`);
  }
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = (req.url ?? "/").split("?")[0];
  const method = req.method ?? "GET";

  // CORS: loopback origins + the paired backend's origin.
  const origin = req.headers.origin;
  if (origin && originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  }
  if (method === "OPTIONS") return void res.writeHead(204).end();

  // The public web plane claims its hostnames FIRST — those hosts never reach /v/ or the API.
  if (await handlePublicWebRequest(req, res)) return;

  // Data plane next — its auth is per-view, not the master token.
  if (url.startsWith("/v/")) {
    if (await handleViewRequest(req, res)) return;
  }

  // Everything below is the control plane: master token required.
  if (!tokenMatches(bearer(req))) return json(res, 401, { error: "unauthorized" });

  // The gate's own log tail — the DAEMON's wire shape ({entries, cursor, dropped}),
  // so the web's server-card Logs modal renders it unchanged.
  if (method === "GET" && url === "/logs") {
    try {
      const { readFileSync } = await import("node:fs");
      const { join } = await import("node:path");
      const { HOME } = await import("./config.js");
      const lines = readFileSync(join(HOME, "isolation-server.log"), "utf8").split("\n").filter(Boolean).slice(-500);
      return json(res, 200, {
        entries: lines.map((line, i) => ({ seq: i, ts: "", stream: "out" as const, line })),
        cursor: lines.length,
        dropped: false,
      });
    } catch {
      return json(res, 200, { entries: [], cursor: 0, dropped: false });
    }
  }

  // Daemon-shaped status (superset: the web reads ok/version/name/relay/sessions/
  // views; the isolation-server-native fields ride along).
  if (method === "GET" && url === "/status") {
    const t = tunnelManager.status();
    return json(res, 200, {
      ok: true,
      version: VERSION,
      name: getName(),
      relay: { connected: t.connected, ...(t.url ? { provider: "cloudflared", publicUrl: t.url } : {}) },
      sessions: listSessionRecords().length,
      views: listSessionRecords().reduce((n, s) => n + sessionViews(s).length, 0),
      maxViews: 28,
      runtime: { kind: "opensandbox", healthy: await osbHealthy() },
      tunnel: t,
      sandbox: sandboxTunnelManager.status(),
      vpc: privateTunnelManager.status(),
      pairing: pairingStatus(),
      // The ssh plane: whether the bastion is configured, whether its control connection is up
      // right now, and the host users type. Routes are soft state — the count is what the bastion
      // currently knows about, not a stored total.
      bastion: bastion.enabled()
        ? { configured: true, connected: bastion.isLive(), host: bastion.publicHost(), edgePort: bastion.edgePort(), routes: bastion.routeCount() }
        : { configured: false },
    });
  }

  // One-step pairing — same flow and body as the daemon's, so `connect` tokens and
  // the cloud's claim endpoint work unchanged: remote cloud → bring up the relay and
  // register its URL; loopback cloud → register the loopback address, no tunnel.
  if (method === "POST" && url === "/pair") {
    const body = await readBody(req);
    const backendUrl = String(body.backendUrl ?? "").trim().replace(/\/+$/, "");
    const code = String(body.code ?? "").trim();
    const label = typeof body.label === "string" && body.label.trim() ? body.label.trim() : getName();
    if (!backendUrl || !code) return json(res, 400, { error: "backendUrl and code required" });
    if (!backendUrlSafe(backendUrl)) return json(res, 400, { error: "invalid or disallowed backendUrl" });
    try {
      if (!isLoopbackOrigin(backendUrl) && !tunnelManager.status().connected) {
        saveEnrollment({ provider: "cloudflared", mode: "quick" });
      }
      await startConfigured({ forceRelay: true });
      if (!isLoopbackOrigin(backendUrl) && !tunnelManager.status().connected) {
        const why = tunnelManager.lastError;
        return json(res, 502, { error: `could not establish a relay tunnel${why ? ` — ${why}` : ""}` });
      }
      const myUrl = isLoopbackOrigin(backendUrl) ? `http://localhost:${PORT}` : (tunnelManager.publicUrl() ?? `http://localhost:${PORT}`);
      const r = await fetch(`${backendUrl}/api/pair/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, url: myUrl, token: getToken(), label, machineId: getMachineId() }),
      });
      const claim = (await r.json().catch(() => ({}))) as { connectionId?: string; secret?: string; label?: string; error?: string };
      if (!r.ok) return json(res, r.status, { error: claim.error ?? `HTTP ${r.status}` });
      if (claim.connectionId && claim.secret) {
        savePairing({ backendUrl, connectionId: claim.connectionId, secret: claim.secret });
        startHeartbeat();
        // The SSH bastion's coords come from the cloud, never hardcoded — same rule as the relay
        // endpoints. Best-effort: a backend with no bastion configured answers `{bastion:null}`,
        // and this server simply stays local-forwarder-only.
        await fetchBastionConfig(backendUrl, claim.connectionId, claim.secret);
        // And the private tunnel the Worker will drive this server through.
        await fetchVpcConfig(backendUrl, claim.connectionId, claim.secret);
      }
      return json(res, 200, { ok: true, label: claim.label ?? label, url: myUrl });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  if (method === "DELETE" && url === "/pair") {
    detach();
    return json(res, 200, { ok: true });
  }

  // --- Sandboxes (MVP surface: enough to exercise the runtime + doorman end to
  // end; the launch orchestration — images, persistence, secrets — lands in O4). ---

  if (method === "POST" && url === "/sandboxes") {
    const body = await readBody(req);
    try {
      return json(res, 201, await launch(body as LaunchRequest));
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  if (method === "GET" && url === "/sandboxes") {
    try {
      const items = await listSandboxes();
      return json(res, 200, {
        items: items.map((s) => ({ ...s, views: viewsForSandbox(s.id) })),
      });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  // ── The local workspace hub (local mode) — the R2 blob contract on loopback ──
  const lw = /^\/local-workspaces\/([A-Za-z0-9._-]+)$/.exec(url);
  if (lw) {
    const { readLocalBlob, writeLocalBlob } = await import("./localsink.js");
    if (method === "GET") {
      const blob = readLocalBlob(lw[1]);
      if (!blob) return json(res, 404, { error: "no bundle yet" });
      if (req.headers["if-none-match"] === blob.etag) {
        res.writeHead(304, { ETag: blob.etag });
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/octet-stream", ETag: blob.etag, "Content-Length": blob.bytes.length });
      res.end(blob.bytes);
      return;
    }
    if (method === "PUT") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const out = writeLocalBlob(lw[1], Buffer.concat(chunks), req.headers["if-match"] as string | undefined, req.headers["if-none-match"] === "*");
      if (!out) return json(res, 400, { error: "bad workspace id" });
      if (out === "conflict") return json(res, 412, { error: "bundle advanced (ETag mismatch)" });
      res.writeHead(200, { ETag: out.etag });
      res.end();
      return;
    }
  }

  // ── The daemon-compatible session surface (PLAN O3) — what the web app drives ──

  if (method === "POST" && url === "/sessions") {
    const body = await readBody(req);
    applyInjectedSandbox(body.sandbox);
    return json(res, 200, sessionJson(startSession(body as DaemonLaunchBody)));
  }

  // Re-fetch the SSH bastion coords for an ALREADY-paired server. Pairing does this too, but a
  // bastion configured (or moved) after a server was paired would otherwise stay unreachable until
  // someone re-paired — and re-pairing is not a thing to ask for a config refresh.
  if (method === "POST" && url === "/bastion") {
    const p = getPairing();
    if (!p) return json(res, 409, { error: "not paired — nothing to fetch bastion coords from" });
    await fetchBastionConfig(p.backendUrl, p.connectionId, p.secret);
    return json(res, 200, { ok: true, bastion: bastion.enabled() ? { host: bastion.publicHost(), connected: bastion.isLive() } : null });
  }

  // Re-fetch the private tunnel + address for an already-paired server (mirrors POST /bastion).
  if (method === "POST" && url === "/vpc") {
    const p = getPairing();
    if (!p) return json(res, 409, { error: "not paired — nothing to fetch a private tunnel from" });
    await fetchVpcConfig(p.backendUrl, p.connectionId, p.secret);
    return json(res, 200, { ok: true, vpc: privateTunnelManager.status() });
  }

  // Configure the public-web tunnel out of band (self-hosters / the cloud on pairing).
  if (method === "POST" && url === "/sandbox") {
    applyInjectedSandbox(await readBody(req));
    return json(res, 200, { ok: true, sandbox: sandboxTunnelManager.status() });
  }
  if (method === "GET" && url === "/sessions") {
    const q = new URL(req.url ?? "/", "http://x").searchParams;
    // Visibility scoping (local mode, daemon contract): CLI-launched sessions are none of the
    // web's business — the DEFAULT excludes origin:"local"; `?origin=local` → only those;
    // `?origin=all` → everything. Filtering, not auth (same user, same token).
    const origin = q.get("origin");
    let all = listSessionRecords(q.get("workspace") ?? undefined);
    if (origin === "local") all = all.filter((r) => r.origin === "local");
    else if (origin !== "all") all = all.filter((r) => r.origin !== "local");
    return json(res, 200, all.map(sessionJson));
  }

  if (method === "GET" && url === "/credentials") {
    // isolation-server discovers nothing on its host by design — credentials come sealed at launch.
    return json(res, 200, { claude: [], github: { present: false } });
  }

  const ag = /^\/agents\/([a-zA-Z0-9-]+)(\/(messages|start))?$/.exec(url);
  if (ag) {
    const [, agentId, , act] = ag;
    const rec = getAgent(agentId);
    if (!rec) return json(res, 404, { error: "unknown agent" });
    if (method === "GET" && !act) return json(res, 200, agentJson(rec));
    // Conversations are per VIEW now (a view is the thread) — talk through /views/:id/messages.
    if (act === "messages") return json(res, 410, { error: "conversations are per view now — use /views/<viewId>/messages" });
    if (method === "POST" && act === "start") return json(res, 200, { ok: startAgent(agentId) });
    if (method === "DELETE" && !act) return json(res, 200, { ok: stopAgent(agentId) });
  }

  if (url.startsWith("/views/")) {
    const vm = /^\/views\/([a-zA-Z0-9-]+)(\/(view-token|messages))?$/.exec(url);
    if (vm) {
      const [, vid, , action] = vm;
      if (method === "POST" && action === "view-token") {
        if (!getView(vid)) return json(res, 404, { error: "unknown view" });
        return json(res, 200, { token: mintViewToken(vid) });
      }
      // THE thread API (PLAN §12 v3): an agent view is a conversation. The control plane talks
      // to it here — the cloud's channel connectors (Slack, Buzz) route a channel to ONE view.
      if (action === "messages") {
        const v = getView(vid);
        if (!v || v.type !== "agent") return json(res, 404, { error: "unknown agent view" });
        if (method === "GET") return json(res, 200, { messages: [] });
        if (method === "POST") {
          const b = await readBody(req);
          const text = typeof b.text === "string" ? b.text : "";
          if (!text.trim()) return json(res, 400, { error: "text required" });
          const out = await connectorTurn(v, text, typeof b.from === "string" ? b.from : "control-plane");
          return "error" in out ? json(res, 502, out) : json(res, 200, out);
        }
      }
      // DELETE means "drop the view" and only ever applies to the bare /views/<id> —
      // a sub-path (…/view-token, …/messages) must never fall through into it.
      if (method === "DELETE" && !action) {
        const gone = getView(vid);
        if (gone?.sshRouteId) bastion.unregisterRoute(gone.sshRouteId);
        const v = dropView(vid);
        // A dropped web view's slug must stop routing at the Worker on the next beat — now.
        if (v?.type === "web") void beatNow();
        // Best-effort: stop the view's in-sandbox server so the port frees up.
        if (v) {
          // Every ported view type owns a process — including a web view's forwarder.
          // Leaving one behind pins its port, and the next view allocated there fails
          // to bind while the stale one keeps pointing at the old app port. Code views
          // are doorman-served (no in-sandbox process) — nothing to kill.
          const pat =
            v.type === "terminal" ? `ttyd .*-p ${v.port}`
            : v.type === "directory" ? `filebrowser .*-p ${v.port}`
            : v.type === "web" ? `portfwd.mjs .* ${v.id}`
            : v.type === "agent" ? bridgePattern(v)
            : undefined;
          // AWAITED: the SPA deletes then immediately recreates on a spec change; an
          // un-awaited kill raced the new view's process on the same port.
          if (pat) await run(v.sandboxId, `pkill -f ${JSON.stringify(pat)} || true`).catch(() => undefined);
          await syncViewsFile(v.sandboxId).catch(() => undefined);
        }
        return json(res, 200, { ok: true });
      }
    }
  }

  // Threads by WORKSPACE-LEVEL key (PLAN §12 v3): the cloud's channel connectors (Slack, Buzz)
  // address a chat as `session + thread key`, never a session-local view id. GET reads the
  // transcript; POST runs a turn — creating the (unplaced) agent view on first contact when the
  // body names the agent, so a channel's first message is enough to start its thread.
  const th = /^\/sessions\/(s-[a-z0-9]+)\/threads\/([A-Za-z0-9._-]+)\/messages$/.exec(url);
  if (th) {
    const [, sid, key] = th;
    const s = getSessionRecord(sid);
    if (!s?.sandboxId) return json(res, 404, { error: "session not ready" });
    let v = viewsForSandbox(s.sandboxId).find((x) => x.type === "agent" && x.specKey === key);
    if (method === "GET") return v ? json(res, 200, { messages: [] }) : json(res, 200, { messages: [] });
    if (method === "POST") {
      const b = await readBody(req);
      const text = typeof b.text === "string" ? b.text : "";
      if (!text.trim()) return json(res, 400, { error: "text required" });
      if (!v) {
        const wanted = typeof b.agentId === "string" ? b.agentId.trim() : "";
        if (!wanted) return json(res, 404, { error: "no such thread in this session (send agentId to start one)" });
        // Resolve against THIS session's roster before scaffolding: an unknown agent would
        // otherwise leave a dangling view (and its process) behind on every failed call.
        const rec = listAgents(sid).find((a) => a.def.id === wanted || a.runtimeId === wanted);
        if (!rec) return json(res, 404, { error: "no such agent in this session" });
        const { scaffoldView } = await import("./launch.js");
        v = await scaffoldView(s.sandboxId, { type: "agent", specKey: key, agentId: rec.def.id, label: typeof b.label === "string" ? b.label : rec.def.name });
        if (!v) return json(res, 502, { error: "could not create the thread's view" });
      }
      const out = await connectorTurn(v, text, typeof b.from === "string" ? b.from : "channel");
      return "error" in out ? json(res, 502, out) : json(res, 200, { ...out, viewId: v.id });
    }
  }

  const sess = /^\/sessions\/(s-[a-z0-9]+)(\/([a-z-]+))?$/.exec(url);
  if (sess) {
    const [, id, , action] = sess;
    const s = getSessionRecord(id);
    if (!s) return json(res, 404, { error: "unknown session" });
    try {
      if (method === "GET" && !action) return json(res, 200, sessionJson(s));
      if (method === "DELETE" && !action) {
        await finishSession(id);
        return json(res, 200, { ok: true });
      }
      if (method === "GET" && action === "views") {
        return json(res, 200, sessionViews(s).map((v) => viewJson(v, id)));
      }
      if (method === "POST" && action === "views") {
        const b = await readBody(req);
        // Agent views (PLAN V2): a doorman-served chat window onto ONE agent. The body
        // either names a roster agent (`agentId` — def or runtime id) or defines a NEW
        // agent inline (`agent: {name, harness?, model?, systemPrompt?}`) which is
        // spawned into the SESSION (not the workspace roster).
        let agentId: string | undefined;
        if (b.type === "agent") {
          const wanted = typeof b.agentId === "string" ? b.agentId.trim() : "";
          if (wanted) {
            const rec = listAgents(id).find((a) => a.def.id === wanted || a.runtimeId === wanted);
            if (!rec) return json(res, 404, { error: "no such agent in this session" });
            agentId = rec.def.id;
            if (!b.label) b.label = rec.def.name;
          } else {
            const inline = parseRoster([{ id: `ag-${Date.now().toString(36)}`, ...(typeof b.agent === "object" && b.agent ? b.agent : {}) }])[0];
            if (!inline) return json(res, 400, { error: "agent view needs agentId or an inline agent {name, …}" });
            const rec = spawnAgent(id, s.workspaceId ?? id, s.sandboxId, inline);
            agentId = rec.def.id;
            if (!b.label) b.label = rec.def.name;
          }
        }
        const v = await createSessionView(s, {
          type: (typeof b.type === "string" ? b.type : "terminal") as never,
          url: typeof b.url === "string" ? b.url : undefined,
          label: typeof b.label === "string" ? b.label : undefined,
          specKey: typeof b.specKey === "string" ? b.specKey : undefined,
          dir: typeof b.dir === "string" ? b.dir : undefined,
          command: typeof b.command === "string" ? b.command : undefined,
          style: b.style,
          agentId,
        });
        if (!v) return json(res, 400, { error: "view spec not satisfiable" });
        // A view added to a live session is reachable over ssh from the moment it exists.
        if (s.sandboxId) syncRoutes(id, s.sandboxId);
        return json(res, 200, viewJson(v, id));
      }
      if (method === "POST" && action === "save") {
        if (!s.sandboxId) return json(res, 409, { error: "session not ready" });
        if (!sinkFor(s.sandboxId)) return json(res, 200, { ok: true, skipped: true, reason: "standalone session (no persistence)" });
        try {
          await saveWorkspace(s.sandboxId);
          return json(res, 200, { ok: true });
        } catch (e) {
          const err = e as Error & { conflict?: boolean };
          return json(res, err.conflict ? 409 : 502, { error: err.message });
        }
      }
      if (method === "POST" && action === "sync") {
        if (!s.sandboxId) return json(res, 409, { error: "session not ready" });
        if (!sinkFor(s.sandboxId)) return json(res, 200, { merged: false, conflict: false, skipped: true, reason: "standalone session (no persistence)" });
        const b = await readBody(req);
        try {
          const out = await syncWorkspace(s.sandboxId, b.resolve === true);
          // Resolve mode: a conflict is the EXPECTED outcome (markers left in the tree,
          // conflicted paths reported) — 200, not 409. Default mode still 409s below.
          return json(res, 200, { merged: out.updated, conflict: out.conflict ?? false, ...(out.conflicts ? { conflicts: out.conflicts } : {}) });
        } catch (e) {
          const err = e as Error & { conflict?: boolean };
          return json(res, err.conflict ? 409 : 502, { error: err.message, merged: false, conflict: !!err.conflict });
        }
      }
      if (method === "POST" && action === "rename") {
        const b = await readBody(req);
        return json(res, 200, sessionJson(renameSession(id, String(b.name ?? "")) ?? s));
      }
      if (method === "GET" && action === "changes") return json(res, 200, await sessionChanges(s));
      if (method === "GET" && action === "logs") {
        if (!s.sandboxId) return json(res, 200, { available: false, lines: [] });
        const text = await sandboxLogs(s.sandboxId).catch(() => undefined);
        if (text === undefined) return json(res, 200, { available: false, lines: [] });
        return json(res, 200, {
          available: true,
          lines: text.split("\n").filter(Boolean).slice(-500).map((line) => ({ ts: "", stream: "out" as const, line })),
        });
      }
      if (method === "GET" && action === "claude-usage") return json(res, 200, { usage: [] });
      if (method === "GET" && action === "agents") return json(res, 200, { agents: listAgents(id).map(agentJson) });
      if (method === "POST" && action === "agents") {
        const b = await readBody(req);
        const def = parseRoster([b])[0];
        if (!def) return json(res, 400, { error: "agent needs id + name" });
        return json(res, 201, agentJson(spawnAgent(id, s.workspaceId ?? id, s.sandboxId, def)));
      }
      if (method === "POST" && action === "stop") {
        const out = await pauseSession(id);
        return out ? json(res, 200, sessionJson(out)) : json(res, 409, { error: "session not ready" });
      }
      if (method === "POST" && action === "start") {
        // Optional `{ vault }` = a fresh sealed manifest to re-install on resume (PLAN §5b).
        const b = await readBody(req).catch(() => ({}) as Record<string, unknown>);
        const out = await resumeSession(id, b.vault);
        return out ? json(res, 200, sessionJson(out)) : json(res, 409, { error: "session not ready" });
      }
      // Not implemented on this runtime yet — explicit, not silent.
      if (["restart", "files", "merge"].includes(action ?? "")) return json(res, 501, { error: "not supported by this server runtime yet" });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }
  // Nested session paths (/sessions/:id/agents/approvals, /files/…, /views/:vid/…).
  // PATCH a live view in place (the daemon contract the web speaks): `label` renames (any type,
  // nothing restarts); `style` re-themes a terminal — ttyd restarts over the same tmux session,
  // so id/port/URL are unchanged and the caller just reloads the iframe.
  const pv = /^\/sessions\/(s-[a-z0-9]+)\/views\/([a-zA-Z0-9-]+)$/.exec(url);
  if (pv && method === "PATCH") {
    const [, id, vid] = pv;
    const s = getSessionRecord(id);
    const v = getView(vid);
    if (!s || !v || v.sandboxId !== s.sandboxId) return json(res, 404, { error: "unknown view" });
    const b = await readBody(req);
    const restyling = "style" in b;
    if (restyling && v.type !== "terminal") return json(res, 400, { error: "only terminal views can be restyled" });
    const patch: Partial<Pick<View, "label" | "style">> = {};
    if (typeof b.label === "string") patch.label = b.label.trim() || undefined;
    if (restyling) patch.style = sanitizeStyle(b.style);
    const nv = updateView(vid, patch) ?? v;
    // The in-sandbox views file carries each view's label — a rename that skipped it would
    // leave the agents' `views` tool naming the window by its old label until the next launch.
    if ("label" in patch) await syncViewsFile(v.sandboxId).catch(() => undefined);
    if (restyling) {
      try {
        await restartTerminal(nv);
      } catch (e) {
        return json(res, 500, { error: `failed to restyle terminal: ${(e as Error).message}` });
      }
    }
    return json(res, 200, viewJson(nv, id));
  }

  // "Open externally" (the daemon's nativeConnect contract): hand the web a ready-to-run `ssh`
  // command for this view. TERMINAL ONLY — it lands in the very tmux session the browser shows,
  // which is the whole point; every other view type is deliberately not connectable (bastion.ts).
  const nc = /^\/sessions\/(s-[a-z0-9]+)\/views\/([a-zA-Z0-9-]+)\/connect$/.exec(url);
  if (nc && method === "POST") {
    const [, id, vid] = nc;
    const s2 = getSessionRecord(id);
    const v = getView(vid);
    if (!s2 || !v || v.sandboxId !== s2.sandboxId) return json(res, 404, { error: "unknown view" });
    if (!modeForView(v.type)) return json(res, 400, { error: `${v.type} views cannot be opened externally` });
    if (!bastion.enabled()) return json(res, 503, { error: "this server has no ssh bastion configured" });
    // A route the bastion holds with an EMPTY allow-list is one nobody can open — and that is the
    // normal state for a member with no ssh public key, because sshd still comes up for the
    // bastion's own agent key. Same rule as the dark-bastion case below: never hand out a command
    // whose only possible answer is "permission denied". Not temporary, so not a 503.
    if (!sshKeysFor(id).length) return json(res, 409, { error: "no ssh public key is authorized for this session — add one to your account and start the session again" });
    // Mint the route id now if the view predates the bastion, and make sure it is actually
    // registered — the answer must not be a command that nothing at the edge would recognize.
    const routeId = ensureRouteId(vid);
    if (!routeId || !s2.sandboxId) return json(res, 503, { error: "ssh is not available for this session" });
    // The bastion's route table is SOFT state that lives only as long as the connection, and
    // `registerRoute` while it is down is a silent no-op that gets replayed on reconnect. Handing
    // out a command in that window would be a lie the user only discovers as "permission denied",
    // so a dark bastion is a 503 here — the reconnect loop makes this answerable again on its own.
    if (!bastion.isLive()) return json(res, 503, { error: "the ssh bastion is not reachable right now" });
    syncRoutes(id, s2.sandboxId);
    const out = nativeConnectFor(routeId, id, vid);
    return out ? json(res, 200, out) : json(res, 503, { error: "the ssh bastion is not reachable right now" });
  }

  const nested = /^\/sessions\/(s-[a-z0-9]+)\/(.+)$/.exec(url);
  if (nested) {
    const sub = nested[2];
    if (method === "POST" && sub === "merge/abort") {
      const s2 = getSessionRecord(nested[1]);
      if (!s2?.sandboxId) return json(res, 404, { error: "unknown session" });
      await abortMerge(s2.sandboxId).catch(() => undefined);
      return json(res, 200, { ok: true });
    }
    if (method === "GET" && sub === "agents/approvals") return json(res, 200, { approvals: [] });
    if (method === "GET" && sub === "agents/harnesses") return json(res, 200, { harnesses: listHarnesses() });
    return json(res, 501, { error: "not supported by this server runtime yet" });
  }

  const sb = /^\/sandboxes\/([a-zA-Z0-9-]+)(\/(pause|resume|save|sync|logs))?$/.exec(url);
  if (sb) {
    const [, id, , action] = sb;
    try {
      if (method === "POST" && (action === "save" || action === "sync")) {
        try {
          const out = action === "save" ? await saveWorkspace(id) : await syncWorkspace(id);
          return json(res, 200, { ok: true, ...out });
        } catch (e) {
          const err = e as Error & { conflict?: boolean };
          return json(res, err.conflict ? 409 : 502, { error: err.message });
        }
      }
      if (method === "DELETE" && !action) {
        await deleteSandbox(id);
        dropSshForSandbox(id);
        dropViewsForSandbox(id);
        invalidateEndpoints(id);
        forgetExecd(id);
        dropSink(id);
        return json(res, 200, { ok: true });
      }
      if (method === "POST" && action === "pause") {
        await pauseSandbox(id);
        return json(res, 200, { ok: true });
      }
      if (method === "POST" && action === "resume") {
        await resumeSandbox(id);
        invalidateEndpoints(id); // published ports may move across a resume
        forgetExecd(id);
        return json(res, 200, { ok: true });
      }
      if (method === "GET" && action === "logs") {
        return json(res, 200, { lines: (await sandboxLogs(id)).split("\n").slice(-500) });
      }
      if (method === "GET" && !action) {
        const s = await getSandbox(id);
        return json(res, 200, { ...s, views: viewsForSandbox(id) });
      }
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  return json(res, 404, { error: "not found" });
}

function makeServer() {
  const server = createServer((req, res) => {
    void route(req, res).catch((e) => {
      if (!res.headersSent) json(res, 500, { error: String((e as Error)?.message ?? e) });
    });
  });
  server.on("upgrade", (req, socket, head) => {
    void handlePublicWebUpgrade(req, socket, head).then((claimed) => {
      if (!claimed) return handleViewUpgrade(req, socket, head);
    });
  });
  return server;
}

// The private-tunnel listener: the same handlers on this server's unique loopback
// ip, which is what the Worker dials over the binding. Still loopback — nothing off-host can reach
// it except through the tunnel. Idempotent, and it FOLLOWS the config: no vpc block (detached) tears
// the listener down, a re-mint on a different ip rebinds — leaving the old socket up would both keep
// a stale way in and silently leave the new address unserved. A bind failure on macOS means the lo0
// alias is missing (`isolation up` adds it) and is reported, not fatal: 127.0.0.1 keeps serving.
let vpcListener: ReturnType<typeof createServer> | undefined;
let vpcListenerIp: string | undefined;
let vpcRetry: NodeJS.Timeout | undefined;
let vpcNagged: string | undefined; // the ip we already complained about — say it once, retry quietly
// Why the private ip is not bound, when it is not. The cloud reaches this server ONLY at that
// address, so an unbound ip means "up but unreachable" — and after a reboot (macOS drops lo0
// aliases, and launchd starts the gate with no terminal to prompt in) nobody would otherwise learn
// why. The heartbeat is outbound and still works, so this rides it to the web UI.
let vpcBindError: string | undefined;
export const vpcStatusDetail = (): string | undefined => vpcBindError;
export function syncVpcListener(): void {
  const ip = getVpc()?.ip;
  if (ip === vpcListenerIp) return;
  clearTimeout(vpcRetry);
  vpcRetry = undefined;
  vpcListener?.close();
  vpcListener = undefined;
  vpcListenerIp = undefined;
  if (!ip) return;
  const s = makeServer();
  s.once("error", (e: NodeJS.ErrnoException) => {
    if (vpcListener === s) {
      vpcListener = undefined;
      vpcListenerIp = undefined;
    }
    // macOS binds nothing but 127.0.0.1 until lo0 gets the alias. Keep retrying: the moment the
    // alias exists the bind succeeds, with no restart of anything — the alias is the only step
    // a person has to take, and it must never also require a second one.
    vpcBindError =
      e.code === "EADDRNOTAVAIL" && process.platform === "darwin"
        ? `the loopback alias for ${ip} is missing (macOS drops them on reboot) — run \`isolation up\` on that machine, or: sudo ifconfig lo0 alias ${ip}`
        : `cannot bind ${ip}:${PORT} (${e.code})`;
    if (vpcNagged !== ip) {
      vpcNagged = ip;
      log(`cannot bind ${ip}:${PORT} (${e.code}) — on macOS run: sudo ifconfig lo0 alias ${ip}  (retrying every 15s until it binds)`);
    }
    vpcRetry = setTimeout(syncVpcListener, 15_000);
    vpcRetry.unref();
  });
  s.listen(PORT, ip, () => {
    vpcNagged = undefined;
    vpcBindError = undefined;
    log(`listening on http://${ip}:${PORT} (private tunnel)`);
  });
  vpcListener = s;
  vpcListenerIp = ip;
}

export function startServer(): void {
  const server = makeServer();
  server.listen(PORT, HOST, () => log(`listening on http://${HOST}:${PORT}`));

  const shutdown = async (): Promise<void> => {
    log("shutting down");
    await beatOffline();
    await tunnelManager.stop();
    await sandboxTunnelManager.stop();
    // The private tunnel is a spawned cloudflared: process.exit() below would orphan it, leaving the
    // Worker's binding connected to a tunnel whose origin is gone — and a second one on the next `up`.
    await privateTunnelManager.stop();
    vpcListener?.close();
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}
