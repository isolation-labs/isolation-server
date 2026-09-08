// The isolation-server HTTP surface — control plane (loopback + tunnel, master-token-gated)
// plus the /v/* data plane (view-token-gated, handled by the doorman). Plain
// node:http: the doorman needs the raw 'upgrade' event anyway, and the API surface
// is small enough that a framework would outweigh it.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { GATE_VERSION } from "./version.js";
import { HOST, PORT, getBastion, getName, getPairing, getToken, getVpc, isLoopbackOrigin, originAllowed, saveBastion, savePairing, saveVpc, tokenMatches, getMachineId } from "./config.js";
import { beatOffline, detach, pairingStatus, startHeartbeat } from "./heartbeat.js";
import { deleteSandbox, getSandbox, listSandboxes, osbHealthy, pauseSandbox, resumeSandbox, sandboxLogs } from "./opensandbox.js";
import { handlePublicWebRequest, handlePublicWebUpgrade, handleViewRequest, handleViewUpgrade, invalidateEndpoints } from "./doorman.js";
import { launch, restartTerminal, sanitizeStyle, type LaunchRequest } from "./launch.js";
import { sinkFor, abortMerge, dropSink, saveWorkspace, syncWorkspace } from "./persistence.js";
import { dropView, dropViewsForSandbox, ensureRouteId, getView, isSlugPrefix, mintViewToken, updateView, viewsForSandbox, type View } from "./views.js";
import { forgetExecd, run } from "./execd.js";
import { agentJson, getAgent, listAgents, parseRoster, spawnAgent, startAgent, stopAgent } from "./agents.js";
import { bridgePattern, connectorTurn, syncViewsFile } from "./acpview.js";
import { attachChannel, channelBinding, channelThreadKey, channelsForSession, detachChannel, rememberEnvelope, type ChatEnvelope } from "./channels.js";
import { listHarnesses } from "./harness.js";
import { pauseSession, resumeSession,
  actorFrom,
  createSessionView,
  dropSshForSandbox,
  finishSession,
  getSessionRecord,
  listSessionRecords,
  mayOpen,
  mayTearDown,
  renameSession,
  sessionForSandbox,
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
  // The private tunnel: the cloud's only way in. The main listener is already up by the time this
  // runs, so the first request the Worker sends after "Registered tunnel connection" lands.
  if (getVpc()) {
    syncVpcListener();
    await privateTunnelManager.start().catch((e: Error) => log(`private tunnel bring-up failed: ${e.message}`));
    // A server paired BEFORE the cloud handed out preview prefixes has creds on disk but no
    // `previewPrefix`, and nothing else ever re-fetches the block: its new web views would mint a
    // bare slug the Worker cannot route (previews only, and silently). One re-fetch at boot in
    // exactly that case — the same idempotent repair POST /vpc runs — and the prefix persists after.
    // The test is `isSlugPrefix`, not "is something there": a prefix persisted in a shape newWebSlug
    // no longer mints with (an older build accepted 6-16 chars) is exactly as unroutable as none at
    // all, and truthiness would let it sit there forever without a single re-ask.
    // NOT on the pair path (`forceRelay`): there the vpc block on disk still belongs to the PREVIOUS
    // pairing, so this would query the old backend and could land its answer — a revocation, even —
    // on top of the fresh one the claim is about to fetch. That path fetches the block itself.
    const paired = getPairing();
    if (!opts?.forceRelay && paired && !isSlugPrefix(getVpc()?.previewPrefix)) {
      void fetchVpcConfig(paired.backendUrl, paired.connectionId, paired.secret);
    }
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

// The server's PRIVATE tunnel (POST /api/pair/vpc — same auth as the bastion coords).
// The cloud claims a pool slot once and returns the same one after; we just run its tunnel.
// A backend with no managed tier answers `{vpc: null}` and this server stays loopback-only.
async function fetchVpcConfig(backendUrl: string, connectionId: string, secret: string): Promise<void> {
  try {
    const r = await fetch(`${backendUrl}/api/pair/vpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connectionId, secret }),
    });
    type VpcAnswer = { vpc?: { creds?: string; previewPrefix?: string; domain?: string } | null };
    // `undefined` = the answer was not JSON at all. That is NOT the cloud speaking, so it must never
    // revoke: an HTML interstitial or a truncated 200 in front of the backend would otherwise cost
    // this server its only way in, and nothing re-fetches on its own afterwards — the cloud would go
    // on dialing a tunnel we no longer run until someone ran `POST /vpc` by hand.
    const body = (await r.json().catch(() => undefined)) as VpcAnswer | undefined;
    if (!r.ok) return log(`vpc config fetch: HTTP ${r.status} — keeping the current one`);
    if (!body || typeof body !== "object") return log("vpc config fetch: the answer was not JSON — keeping the current one");
    const v = body.vpc;
    const creds = typeof v?.creds === "string" && v.creds ? v.creds : undefined;
    if (!creds) {
      // A well-formed answer carrying a MALFORMED block is a backend bug, not a revocation either —
      // only an explicit `{vpc: null}` is the cloud saying this server has no private tunnel.
      if (v) return log("vpc config fetch: malformed vpc block — keeping the current one");
      // A HEALTHY backend saying "no private tunnel" revokes the one we hold — same rule as the
      // bastion coords, and unlike the sandbox config the vpc block has no self-hoster provenance:
      // only the cloud ever mints it. Left alone it would keep an inbound path open for a cloud (or
      // an account) that no longer owns this server — this is exactly the re-pair-elsewhere case —
      // and this server would go on answering a tunnel the new cloud can never reach.
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
    // A slot RECYCLE rotates the tunnel's secret while keeping its id, so a changed credential for
    // the same server is normal and must restart cloudflared with the new one.
    const unchanged = cur?.creds === creds;
    // The preview prefix rides along: new web views prefix their slug with it (views.ts newWebSlug).
    // Persisted even when the creds did not change, so a server paired before prefixes were handed
    // out picks it up on its next `up` / POST /vpc without a tunnel restart.
    // Exactly the shape newWebSlug will actually use — anything else is dropped rather than stored,
    // so the boot repair above keeps re-asking instead of silently minting unroutable bare slugs.
    const previewPrefix = isSlugPrefix(v?.previewPrefix) ? v.previewPrefix : undefined;
    if (v?.previewPrefix != null && previewPrefix === undefined) log("the cloud sent a preview prefix of an unexpected shape — ignored; web views stay on <slug>.localhost");
    if (!unchanged) saveVpc({ creds, ...(previewPrefix ? { previewPrefix } : {}) });
    else if (previewPrefix && cur?.previewPrefix !== previewPrefix) saveVpc({ ...cur!, previewPrefix });
    if (!unchanged) await privateTunnelManager.stop();
    await privateTunnelManager.start().catch((e: Error) => log(`private tunnel failed: ${e.message}`));
    // The public quick tunnel has no job left: everything reaches this server through the Worker.
    if (!isLoopbackOrigin(backendUrl)) void tunnelManager.stop();
    if (unchanged) return;
    log(`private tunnel configured — the cloud reaches this server over its tunnel at 127.0.0.1:${PORT}`);
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
  // …and, through the Worker proxy, WHICH member holds it (sessions.ts: a session is its
  // launcher's; a foreign one is a 404 everywhere except the list + DELETE an org admin gets).
  const actor = actorFrom(req.headers);

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
      // The ops list: an org admin sees a teammate's sandbox, but the VIEWS ride along raw — and a
      // web view's `slug` IS its access (the public plane authenticates on the slug alone). Listing
      // is not opening, so the views come only with the session, never with the admin exception.
      return json(res, 200, {
        items: items
          .map((s) => ({ s, owning: sessionForSandbox(s.id) }))
          .filter(({ owning }) => mayTearDown(actor, owning))
          .map(({ s, owning }) => ({ ...s, views: mayOpen(actor, owning) ? viewsForSandbox(s.id) : [] })),
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
    return json(res, 200, sessionJson(startSession(body as DaemonLaunchBody, actor?.id)));
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
    // The member's own — plus everyone's for an org owner/admin (the ops list; `owner` names whose).
    return json(res, 200, all.filter((r) => mayTearDown(actor, r)).map(sessionJson));
  }

  if (method === "GET" && url === "/credentials") {
    // isolation-server discovers nothing on its host by design — credentials come sealed at launch.
    return json(res, 200, { claude: [], github: { present: false } });
  }

  const ag = /^\/agents\/([a-zA-Z0-9-]+)(\/(messages|start))?$/.exec(url);
  if (ag) {
    const [, agentId, , act] = ag;
    const rec = getAgent(agentId);
    if (!rec || !mayOpen(actor, getSessionRecord(rec.sessionId))) return json(res, 404, { error: "unknown agent" });
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
      // A view is content: reachable by its session's launcher only (a view token IS access).
      const owning = getView(vid);
      if (owning && !mayOpen(actor, sessionForSandbox(owning.sandboxId))) return json(res, 404, { error: "unknown view" });
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
        // AWAITED, and before the view is dropped: the control-channel pump for an agent view is
        // keyed by view id, and view ports are recycled. A pump left running would keep polling
        // the port this delete frees and could be handed the NEXT view's tool calls (PLAN §1 I3).
        await import("./toolpump.js").then((m) => m.stopToolPump(vid));
        const v = dropView(vid);
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
    if (!s?.sandboxId || !mayOpen(actor, s)) return json(res, 404, { error: "session not ready" });
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
      // WHERE this message came from (PLAN §1 I3): the agent asks for it with `chat_context`, and
      // `chat_reply` answers in the same thread. Remembered per thread key — one live envelope per
      // conversation, which is exactly what "the message I am answering" means.
      const envelope = parseEnvelope(b.envelope);
      rememberEnvelope(sid, key, envelope);
      const from = typeof b.from === "string" ? b.from : envelope ? `${envelope.connector}:${envelope.senderName ?? envelope.sender ?? "someone"}` : "channel";
      // A connector that cannot hold a request open for a turn that takes minutes (Slack must ack
      // in three seconds) asks for the reply to be delivered instead: we answer at once and the
      // agent's own `chat_reply` carries the answer back when the turn ends.
      if (b.async === true) {
        // The same tail Buzz's relay path runs (channelturn.ts): find the thread's view, take the
        // turn, post the answer back. One door, so a Slack turn and a Buzz turn cannot drift.
        const view = v;
        void (async () => {
          const { deliverChannelTurn } = await import("./channelturn.js");
          await deliverChannelTurn(sid, key, view.agentId ?? "", text, envelope ?? { connector: "channel", channel: key });
        })().catch((e: Error) => log(`${sid}/${key}: async turn threw — ${e?.message ?? e}`));
        return json(res, 202, { accepted: true, viewId: v.id });
      }
      const out = await connectorTurn(v, text, from);
      return "error" in out ? json(res, 502, out) : json(res, 200, { ...out, viewId: v.id });
    }
  }

  // A chat bound to this session (PLAN §1 I3): the cloud attaches a channel with the agents that
  // are in it, and detaches when it is disconnected. The binding is what makes an inbound mention
  // find its thread and an outbound `chat_post` find its channel.
  const ch = /^\/sessions\/(s-[a-z0-9]+)\/channels(\/([A-Za-z0-9-]+))?$/.exec(url);
  if (ch) {
    const [, sid, , bindingId] = ch;
    const s = getSessionRecord(sid);
    if (!s || !mayOpen(actor, s)) return json(res, 404, { error: "unknown session" });
    if (method === "GET") return json(res, 200, { channels: channelsForSession(sid) });
    if (method === "POST" && !bindingId) {
      const b = await readBody(req);
      const connector = typeof b.connector === "string" ? b.connector.trim().slice(0, 30) : "";
      const channel = typeof b.channel === "string" ? b.channel.trim().slice(0, 200) : "";
      if (!connector || !channel) return json(res, 400, { error: "connector and channel required" });
      const wanted = Array.isArray(b.agents) ? b.agents.filter((a: unknown): a is string => typeof a === "string") : [];
      // Only agents this session actually runs — a binding naming a stranger would route a
      // mention into a thread with nobody in it.
      const roster = listAgents(sid);
      const agents = (wanted.length ? wanted : roster.map((a) => a.def.id)).filter((id) => roster.some((a) => a.def.id === id));
      if (!agents.length) return json(res, 400, { error: "none of those agents are in this session" });
      const bind = attachChannel({ sessionId: sid, connector, channel, channelName: typeof b.channelName === "string" ? b.channelName.slice(0, 200) : undefined, agents });
      // BUZZ runs here rather than on the cloud (PLAN §1 I5): reading a channel means holding a
      // relay subscription and posting means signing with the agent's own key. Both arrive sealed
      // with the binding and live only in this process's memory.
      let npubs: Record<string, string> | undefined;
      if (connector === "buzz") {
        try {
          const relay = typeof b.relay === "string" ? b.relay : "";
          if (!relay) throw new Error("a buzz binding needs the relay to connect to");
          const keys = parseAgentKeys(b.keys, agents);
          if (!keys.length) throw new Error("a buzz binding needs each agent's own key");
          npubs = (await (await import("./buzz.js")).attachBuzz(bind, { relay, keys })).npubs;
        } catch (e) {
          // The binding is not left half-made: a chat we cannot actually read or write to would
          // sit in the list looking connected and answer nothing.
          detachChannel(bind.id);
          return json(res, 502, { error: `could not connect to Buzz: ${String((e as Error)?.message ?? e)}` });
        }
      }
      return json(res, 201, { ...bind, ...(npubs ? { npubs } : {}), threads: agents.map((a) => ({ agentId: a, threadKey: channelThreadKey(connector, channel, a) })) });
    }
    if (method === "DELETE" && bindingId) {
      // A binding id is only ever detachable through the session it belongs to: the id is the
      // only thing the caller supplies, and `mayOpen` above answers for THIS session — not for
      // whichever session the id happens to name.
      if (channelBinding(bindingId)?.sessionId !== sid) return json(res, 404, { error: "unknown binding" });
      const gone = detachChannel(bindingId);
      return gone ? json(res, 200, { ok: true }) : json(res, 404, { error: "unknown binding" });
    }
  }

  const sess = /^\/sessions\/(s-[a-z0-9]+)(\/([a-z-]+))?$/.exec(url);
  if (sess) {
    const [, id, , action] = sess;
    const s = getSessionRecord(id);
    if (!s) return json(res, 404, { error: "unknown session" });
    // The bare GET (the list card's poll) and the bare DELETE are the ops pair an org admin gets
    // on anyone's session; every other action opens it and is the launcher's alone.
    const ops = !action && (method === "GET" || method === "DELETE");
    if (!(ops ? mayTearDown(actor, s) : mayOpen(actor, s))) return json(res, 404, { error: "unknown session" });
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
    if (!s || !v || v.sandboxId !== s.sandboxId || !mayOpen(actor, s)) return json(res, 404, { error: "unknown view" });
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
    if (!s2 || !v || v.sandboxId !== s2.sandboxId || !mayOpen(actor, s2)) return json(res, 404, { error: "unknown view" });
    if (!modeForView(v.type)) return json(res, 400, { error: `${v.type} views cannot be opened externally` });
    if (!bastion.enabled()) return json(res, 503, { error: "this server has no ssh bastion configured" });
    // sshd never came up in this sandbox. Two causes, both settled at launch time: the image had no
    // openssh-server, or the launch carried neither an authorized key nor a bastion key, so
    // `startSshAccess` was never called (launch.ts). The bastion would accept the connection and
    // then fail the hop with a 502 nobody can act on; say so here instead. Not temporary, so not a
    // 503. The signal is the record's `sshd`, NOT its `sshPort`: the port belongs to a local
    // forwarder this process binds, and it is dropped and re-bound on every restart (sessions.ts)
    // while the bastion hop never touches it — reading the port here would tell a member with a
    // perfectly healthy session to throw it away. And it is only settled once the launch IS: views
    // are scaffolded (and listed to the web) while the session is still `creating`, so answer
    // "not yet" until then. `sshd` undefined on a finished session = a record from before the
    // field existed: unknown, so fall through rather than refuse.
    if (s2.state === "creating") return json(res, 503, { error: "this session is still starting — ssh is not up yet" });
    if (s2.sshd === false) return json(res, 409, { error: "ssh was never brought up in this session — start a new session (its sandbox has no sshd running)" });
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
    if (!mayOpen(actor, getSessionRecord(nested[1]))) return json(res, 404, { error: "unknown session" });
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
    // A sandbox that backs a session is that session's: same launcher-only rule, same
    // admin-may-delete exception (a raw sandbox with no session stays as open as before).
    const backing = sessionForSandbox(id);
    if (backing && !(method === "DELETE" && !action ? mayTearDown(actor, backing) : mayOpen(actor, backing))) return json(res, 404, { error: "unknown sandbox" });
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
        // Before the views go, not after: `stopToolPumpsFor` finds its pumps THROUGH the
        // sandbox's views, so a call placed below would have nothing left to stop (PLAN §1 I3).
        await import("./toolpump.js").then((m) => m.stopToolPumpsFor(id));
        dropViewsForSandbox(id);
        invalidateEndpoints(id);
        forgetExecd(id);
        dropSink(id);
        return json(res, 200, { ok: true });
      }
      if (method === "POST" && action === "pause") {
        // Same rule as pauseSession: the bridges stop with the sandbox, and a pump left polling
        // one would burn its retry budget and give up FOR GOOD — the raw resume below re-arms it.
        await import("./toolpump.js").then((m) => m.stopToolPumpsFor(id));
        await pauseSandbox(id);
        return json(res, 200, { ok: true });
      }
      if (method === "POST" && action === "resume") {
        await resumeSandbox(id);
        invalidateEndpoints(id); // published ports may move across a resume
        forgetExecd(id);
        await import("./toolpump.js").then((m) => m.startToolPumpsFor(id)); // the agents can reach out again
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

// There is no second listener any more. The Worker reaches this server through the `vpc_networks`
// binding pinned to its pool tunnel, and everything behind that tunnel is just 127.0.0.1:8090 — the
// binding is the selector, so no per-server address exists to bind. (Until 2026-09-08 the cloud
// allocated one loopback ip per server and this bound it too, which needed `sudo ifconfig lo0 alias`
// on macOS and silently broke on every reboot.)
//
// Kept as a no-op so the call sites that follow config changes (pairing, POST /vpc, detach) do not
// have to care, and so an older config with a stale `ip` cannot resurrect the old behaviour.
export function syncVpcListener(): void {}

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
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

// The chat envelope a connector sends with an inbound turn. Bounded and shape-checked here because
// it comes from OUTSIDE (the cloud relays what a chat app said), and it is shown to an agent.
function parseEnvelope(raw: unknown): ChatEnvelope | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  const str = (v: unknown, max = 200): string | undefined => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined);
  const connector = str(o.connector, 30);
  const channel = str(o.channel);
  if (!connector || !channel) return undefined;
  return {
    connector,
    channel,
    ...(str(o.channelName) ? { channelName: str(o.channelName)! } : {}),
    ...(o.direct === true ? { direct: true } : {}),
    ...(str(o.sender) ? { sender: str(o.sender)! } : {}),
    ...(str(o.senderName) ? { senderName: str(o.senderName)! } : {}),
    ...(str(o.messageId) ? { messageId: str(o.messageId)! } : {}),
    ...(str(o.thread) ? { thread: str(o.thread)! } : {}),
  };
}

/**
 * The per-agent secret keys a Buzz binding carries. They arrive SEALED with the binding (the launch
 * envelope's own encryption) and are held only in memory for the life of the connection — never
 * written to disk, never logged, and never handed to a sandbox: the relay client that uses them
 * runs in this process, which is the reason Buzz is served here at all.
 */
function parseAgentKeys(raw: unknown, allowed: string[]): { agentId: string; name: string; nsec: string }[] {
  const list = Array.isArray(raw) ? raw : [];
  const out: { agentId: string; name: string; nsec: string }[] = [];
  for (const k of list) {
    const o = (k ?? {}) as Record<string, unknown>;
    const agentId = typeof o.agentId === "string" ? o.agentId : "";
    const nsec = typeof o.nsec === "string" ? o.nsec.trim() : "";
    // Only for an agent this binding actually carries — a key for anyone else has no business here.
    if (!agentId || !nsec || !allowed.includes(agentId)) continue;
    out.push({ agentId, name: typeof o.name === "string" && o.name ? o.name.slice(0, 80) : agentId, nsec });
  }
  return out;
}
