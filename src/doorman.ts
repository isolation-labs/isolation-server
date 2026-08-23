// The doorman — isogate's data plane. One public origin (the tunnel) fronts every
// view of every sandbox:  /v/<viewId>/*  →  the sandbox port, via the runtime's
// per-sandbox proxy (execd publishes one host port; its /proxy/<port> path forwards
// to the app port inside the sandbox). WebSocket-capable.
//
// Browser auth (ported contract): a browser can't set Authorization on an iframe or
// WS handshake, so we accept the master token OR a view-scoped token via `?token=`
// or the `isogate_token` cookie; a valid query token is promoted to a Path=/v/<id>
// cookie so subsequent asset/WS requests authenticate automatically.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import httpProxy from "http-proxy-3";
import { tokenMatches } from "./config.js";
import { endpointFor } from "./opensandbox.js";
import { getView, verifyViewToken } from "./views.js";

const proxy = httpProxy.createProxyServer({ ws: true, xfwd: true });
proxy.on("error", (err, _req, res) => {
  const r = res as ServerResponse | Duplex | undefined;
  if (r && "writeHead" in r && !r.headersSent) {
    r.writeHead(502, { "Content-Type": "application/json" });
    r.end(JSON.stringify({ error: `upstream unreachable: ${err.message}` }));
  } else if (r && "destroy" in r) {
    (r as Duplex).destroy();
  }
});

// Strip iframe blockers so views render embedded in the web app (X-Frame-Options has
// no per-origin allow; for CSP remove only frame-ancestors, keep the rest).
proxy.on("proxyRes", (proxyRes) => {
  const h = proxyRes.headers;
  delete h["x-frame-options"];
  for (const key of ["content-security-policy", "content-security-policy-report-only"] as const) {
    const v = h[key];
    if (v === undefined) continue;
    const clean = (csp: string) =>
      csp
        .split(";")
        .map((d) => d.trim())
        .filter((d) => d && !/^frame-ancestors\b/i.test(d))
        .join("; ");
    const cleaned = Array.isArray(v) ? v.map(clean).filter(Boolean) : clean(v);
    if (!cleaned || (Array.isArray(cleaned) && !cleaned.length)) delete h[key];
    else h[key] = cleaned;
  }
});

const VIEW_RE = /^\/v\/([a-zA-Z0-9-]+)(\/.*)?$/;

export const viewIdFromUrl = (url: string | undefined): string | undefined => VIEW_RE.exec((url ?? "").split("?")[0])?.[1];

function tokenFromRequest(req: IncomingMessage, viewId: string): string | undefined {
  const u = new URL(req.url ?? "/", "http://x");
  const q = u.searchParams.get("token");
  if (q) return q;
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  const cookies = req.headers.cookie ?? "";
  for (const c of cookies.split(";")) {
    const [k, ...rest] = c.trim().split("=");
    if (k === "isogate_token") return decodeURIComponent(rest.join("="));
  }
  void viewId;
  return undefined;
}

const authorized = (req: IncomingMessage, viewId: string): { ok: boolean; queryToken?: string } => {
  const t = tokenFromRequest(req, viewId);
  const ok = !!t && (tokenMatches(t) || verifyViewToken(t, viewId));
  const u = new URL(req.url ?? "/", "http://x");
  return { ok, queryToken: u.searchParams.get("token") ?? undefined };
};

// Endpoint cache: the published host port is stable for a running sandbox; drop the
// entry on proxy failure or sandbox lifecycle changes so a resume re-resolves.
const targets = new Map<string, { host: string; basePath: string }>();
export const invalidateEndpoints = (sandboxId?: string): void => {
  if (!sandboxId) targets.clear();
  else for (const [k, _] of targets) if (k.startsWith(`${sandboxId}:`)) targets.delete(k);
};

async function resolveTarget(sandboxId: string, port: number): Promise<{ host: string; basePath: string }> {
  const key = `${sandboxId}:${port}`;
  const hit = targets.get(key);
  if (hit) return hit;
  const ep = await endpointFor(sandboxId, port);
  targets.set(key, ep);
  return ep;
}

// Rewrites /v/<id>/rest → <basePath>/rest and proxies. Returns true when the URL was
// a view path (handled here, success or error).
export async function handleViewRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const m = VIEW_RE.exec((req.url ?? "").split("?")[0]);
  if (!m) return false;
  const viewId = m[1];
  const view = getView(viewId);
  if (!view) {
    res.writeHead(404, { "Content-Type": "application/json" }).end(JSON.stringify({ error: "unknown view" }));
    return true;
  }
  const { ok, queryToken } = authorized(req, viewId);
  if (!ok) {
    res.writeHead(401, { "Content-Type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
    return true;
  }
  // Promote a valid query token to a view-scoped cookie for the follow-up requests.
  if (queryToken) {
    res.setHeader("Set-Cookie", `isogate_token=${encodeURIComponent(queryToken)}; Path=/v/${viewId}; HttpOnly; SameSite=None; Secure`);
  }
  try {
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${viewPath(view, req.url, viewId)}`;
    proxy.web(req, res, { target: `http://${t.host}` });
  } catch (e) {
    targets.delete(`${view.sandboxId}:${view.port}`);
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: String((e as Error)?.message ?? e) }));
  }
  return true;
}

// Most view servers see stripped, base-relative paths (they emit relative asset
// URLs). A directory view's filebrowser is configured WITH its /v/<id> base URL,
// so it receives the path unstripped.
function viewPath(view: { type: string }, url: string | undefined, viewId: string): string {
  if (view.type === "directory") return url ?? "/";
  return (url ?? "").slice(`/v/${viewId}`.length) || "/";
}

export async function handleViewUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
  const viewId = viewIdFromUrl(req.url);
  const view = viewId ? getView(viewId) : undefined;
  if (!viewId || !view || !authorized(req, viewId).ok) {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }
  try {
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${viewPath(view, req.url, viewId)}`;
    proxy.ws(req, socket, head, { target: `http://${t.host}` });
  } catch {
    targets.delete(`${view.sandboxId}:${view.port}`);
    socket.destroy();
  }
}
