// The isogate HTTP surface — control plane (loopback + tunnel, master-token-gated)
// plus the /v/* data plane (view-token-gated, handled by the doorman). Plain
// node:http: the doorman needs the raw 'upgrade' event anyway, and the API surface
// is small enough that a framework would outweigh it.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { HOST, PORT, getName, getPairing, getToken, isLoopbackOrigin, originAllowed, savePairing, tokenMatches } from "./config.js";
import { beatOffline, detach, pairingStatus, startHeartbeat } from "./heartbeat.js";
import { deleteSandbox, getSandbox, listSandboxes, osbHealthy, pauseSandbox, resumeSandbox, sandboxLogs } from "./opensandbox.js";
import { handleViewRequest, handleViewUpgrade, invalidateEndpoints } from "./doorman.js";
import { launch, type LaunchRequest } from "./launch.js";
import { dropSink, saveWorkspace, syncWorkspace } from "./persistence.js";
import { dropViewsForSandbox, viewsForSandbox } from "./views.js";
import { forgetExecd } from "./execd.js";
import { tunnelManager } from "./tunnel.js";

const VERSION = "0.0.1";
const log = (...a: unknown[]) => console.log("[isogate]", ...a);

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
import { getEnrollment, saveEnrollment } from "./config.js";
export async function startConfigured(): Promise<void> {
  if (getEnrollment() && !tunnelManager.status().connected) {
    try {
      await tunnelManager.start();
    } catch (e) {
      log(`tunnel bring-up failed: ${String((e as Error)?.message ?? e)}`);
    }
  }
  if (getPairing()) startHeartbeat();
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

  // Data plane first — its auth is per-view, not the master token.
  if (url.startsWith("/v/")) {
    if (await handleViewRequest(req, res)) return;
  }

  // Everything below is the control plane: master token required.
  if (!tokenMatches(bearer(req))) return json(res, 401, { error: "unauthorized" });

  // The gate's own log tail (the web's server-card "Logs" contract).
  if (method === "GET" && url === "/logs") {
    try {
      const { readFileSync } = await import("node:fs");
      const { join } = await import("node:path");
      const { HOME } = await import("./config.js");
      const lines = readFileSync(join(HOME, "isogate.log"), "utf8").split("\n");
      return json(res, 200, { lines: lines.slice(-500) });
    } catch {
      return json(res, 200, { lines: [] });
    }
  }

  if (method === "GET" && url === "/status") {
    return json(res, 200, {
      version: VERSION,
      name: getName(),
      runtime: { kind: "opensandbox", healthy: await osbHealthy() },
      tunnel: tunnelManager.status(),
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
    void handleViewUpgrade(req, socket, head);
  });
  server.listen(PORT, HOST, () => log(`listening on http://${HOST}:${PORT}`));

  const shutdown = async (): Promise<void> => {
    log("shutting down");
    await beatOffline();
    await tunnelManager.stop();
    server.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}
