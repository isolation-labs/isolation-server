// The isolation-server HTTP surface — control plane (loopback + tunnel, master-token-gated)
// plus the /v/* data plane (view-token-gated, handled by the doorman). Plain
// node:http: the doorman needs the raw 'upgrade' event anyway, and the API surface
// is small enough that a framework would outweigh it.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { GATE_VERSION } from "./version.js";
import { HOST, PORT, getName, getPairing, getToken, isLoopbackOrigin, originAllowed, savePairing, tokenMatches } from "./config.js";
import { beatOffline, detach, pairingStatus, startHeartbeat } from "./heartbeat.js";
import { deleteSandbox, getSandbox, listSandboxes, osbHealthy, pauseSandbox, resumeSandbox, sandboxLogs } from "./opensandbox.js";
import { handlePublicWebRequest, handlePublicWebUpgrade, handleViewRequest, handleViewUpgrade, invalidateEndpoints } from "./doorman.js";
import { launch, type LaunchRequest } from "./launch.js";
import { sinkFor, abortMerge, dropSink, saveWorkspace, syncWorkspace } from "./persistence.js";
import { dropView, dropViewsForSandbox, getView, mintViewToken, viewsForSandbox } from "./views.js";
import { forgetExecd, run } from "./execd.js";
import { agentJson, getAgent, listAgents, parseRoster, sendMessage, spawnAgent, startAgent, stopAgent } from "./agents.js";
import { listHarnesses } from "./harness.js";
import { pauseSession, resumeSession,
  createSessionView,
  finishSession,
  getSessionRecord,
  listSessionRecords,
  renameSession,
  sessionChanges,
  sessionJson,
  sessionViews,
  startSession,
  viewJson,
  type DaemonLaunchBody,
} from "./sessions.js";
import { sandboxTunnelManager, tunnelManager } from "./tunnel.js";

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
export async function startConfigured(): Promise<void> {
  if (getEnrollment() && !tunnelManager.status().connected) {
    try {
      await tunnelManager.start();
    } catch (e) {
      log(`tunnel bring-up failed: ${String((e as Error)?.message ?? e)}`);
    }
  }
  if (getPairing()) startHeartbeat();
  if (getSandboxConfig() && !sandboxTunnelManager.status().connected) {
    await sandboxTunnelManager.start().catch((e: Error) => log(`sandbox tunnel bring-up failed: ${e.message}`));
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
  if (!domain || !creds) return;
  const cur = getSandboxConfig();
  if (cur && cur.domain === domain && cur.creds === creds) return;
  saveSandbox({ provider: "cloudflared", creds, domain });
  void sandboxTunnelManager.start().catch((e: Error) => log(`sandbox tunnel (injected) failed: ${e.message}`));
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = (req.url ?? "/").split("?")[0];
  const method = req.method ?? "GET";

  // CORS: loopback origins + the paired backend's origin.
  const origin = req.headers.origin;
  if (origin && originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
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
      pairing: pairingStatus(),
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
      await startConfigured();
      if (!isLoopbackOrigin(backendUrl) && !tunnelManager.status().connected) {
        const why = tunnelManager.lastError;
        return json(res, 502, { error: `could not establish a relay tunnel${why ? ` — ${why}` : ""}` });
      }
      const myUrl = isLoopbackOrigin(backendUrl) ? `http://localhost:${PORT}` : (tunnelManager.publicUrl() ?? `http://localhost:${PORT}`);
      const r = await fetch(`${backendUrl}/api/pair/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, url: myUrl, token: getToken(), label }),
      });
      const claim = (await r.json().catch(() => ({}))) as { connectionId?: string; secret?: string; label?: string; error?: string };
      if (!r.ok) return json(res, r.status, { error: claim.error ?? `HTTP ${r.status}` });
      if (claim.connectionId && claim.secret) {
        savePairing({ backendUrl, connectionId: claim.connectionId, secret: claim.secret });
        startHeartbeat();
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
    if (method === "GET" && !act) return json(res, 200, { ...agentJson(rec), conversation: rec.conversation });
    if (method === "GET" && act === "messages") return json(res, 200, { messages: rec.conversation });
    if (method === "POST" && act === "messages") {
      const b = await readBody(req);
      const text = typeof b.text === "string" ? b.text : "";
      if (!text.trim()) return json(res, 400, { error: "text required" });
      const out = await sendMessage(agentId, text, typeof b.from === "string" ? b.from : "sidebar");
      return "error" in out ? json(res, 502, out) : json(res, 200, out);
    }
    if (method === "POST" && act === "start") return json(res, 200, { ok: startAgent(agentId) });
    if (method === "DELETE" && !act) return json(res, 200, { ok: stopAgent(agentId) });
  }

  if (url.startsWith("/views/")) {
    const vm = /^\/views\/([a-zA-Z0-9-]+)(\/view-token)?$/.exec(url);
    if (vm) {
      const [, vid, tokenAction] = vm;
      if (method === "POST" && tokenAction) {
        if (!getView(vid)) return json(res, 404, { error: "unknown view" });
        return json(res, 200, { token: mintViewToken(vid) });
      }
      if (method === "DELETE" && !tokenAction) {
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
            : undefined;
          // AWAITED: the SPA deletes then immediately recreates on a spec change; an
          // un-awaited kill raced the new view's process on the same port.
          if (pat) await run(v.sandboxId, `pkill -f ${JSON.stringify(pat)} || true`).catch(() => undefined);
        }
        return json(res, 200, { ok: true });
      }
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
        // The agent chat embed is a daemon-side view type isolation-server doesn't host (the
        // agent layer lands in O5); refuse explicitly rather than minting a dead view.
        if (b.type === "agent") return json(res, 501, { error: "agent views are not supported by this server runtime yet" });
        const v = await createSessionView(s, {
          type: (typeof b.type === "string" ? b.type : "terminal") as never,
          url: typeof b.url === "string" ? b.url : undefined,
          label: typeof b.label === "string" ? b.label : undefined,
          specKey: typeof b.specKey === "string" ? b.specKey : undefined,
        });
        if (!v) return json(res, 400, { error: "view spec not satisfiable" });
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
        const out = await resumeSession(id);
        return out ? json(res, 200, sessionJson(out)) : json(res, 409, { error: "session not ready" });
      }
      // Not implemented on this runtime yet — explicit, not silent.
      if (["restart", "files", "merge"].includes(action ?? "")) return json(res, 501, { error: "not supported by this server runtime yet" });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }
  // Nested session paths (/sessions/:id/agents/approvals, /files/…, /views/:vid/…).
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

export function startServer(): void {
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
  server.listen(PORT, HOST, () => log(`listening on http://${HOST}:${PORT}`));

  const shutdown = async (): Promise<void> => {
    log("shutting down");
    await beatOffline();
    await tunnelManager.stop();
    await sandboxTunnelManager.stop();
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}
