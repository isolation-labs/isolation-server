// The doorman — isolation-server's data plane. One public origin (the tunnel) fronts every
// view of every sandbox:  /v/<viewId>/*  →  the sandbox port, via the runtime's
// per-sandbox proxy (execd publishes one host port; its /proxy/<port> path forwards
// to the app port inside the sandbox). WebSocket-capable.
//
// Browser auth (ported contract): a browser can't set Authorization on an iframe or
// WS handshake, so we accept the master token OR a view-scoped token via `?token=`
// or the `isolation-server_token` cookie; a valid query token is promoted to a Path=/v/<id>
// cookie so subsequent asset/WS requests authenticate automatically.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import httpProxy from "http-proxy-3";
import { getSandbox, tokenMatches } from "./config.js";
import { endpointFor } from "./opensandbox.js";
import { getView, verifyViewToken, viewBySlug, type View } from "./views.js";
import { startWebForwarder, webForwarderAlive } from "./launch.js";
import { handleCodeView } from "./codeview.js";
import { handleAgentView } from "./agentview.js";
import { handleGitView } from "./gitview.js";

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
    if (k === "isolation-server_token") return decodeURIComponent(rest.join("="));
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
    res.setHeader("Set-Cookie", `isolation-server_token=${encodeURIComponent(queryToken)}; Path=/v/${viewId}; HttpOnly; SameSite=None; Secure`);
  }
  // Code and agent views are first-party (PLAN V1/V2): the doorman serves the app and
  // its API itself — there is no sandbox port to proxy to.
  if (view.type === "code") {
    await handleCodeView(req, res, view, m[2] || "/");
    return true;
  }
  if (view.type === "agent") {
    await handleAgentView(req, res, view, m[2] || "/");
    return true;
  }
  if (view.type === "git") {
    await handleGitView(req, res, view, m[2] || "/");
    return true;
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
  if (!viewId || !view || view.type === "code" || view.type === "agent" || view.type === "git" || !authorized(req, viewId).ok) {
    // Code/agent views are doorman-served static pages + REST — no WebSocket to upgrade to.
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

// --- The public web plane (sandbox hostnames) -----------------------------------
// A web view is reachable at `<slug>.<sandboxDomain>` over the wildcard sandbox tunnel,
// or `<slug>.localhost` on a connected/local server (browsers resolve *.localhost to
// loopback with no DNS). We route by Host — NOT a /v/ path — so the app sits at `/` and
// its root-absolute asset URLs resolve. This plane is PUBLIC + unauthenticated by
// design (the slug is the secret: ≥128-bit, unguessable) and it claims sandbox hosts
// whole: the token-gated API and /v/ views are never reachable on these hostnames.

const hostOnly = (h: string | undefined): string => (h ?? "").split(":")[0].trim().toLowerCase();

// The slug when this request's Host belongs to the public plane; undefined otherwise.
// A configured sandbox domain claims ALL its subdomains (unknown slug → 404, never the
// API). `.localhost` claims only labels that match a live web view, so plain
// `localhost` keeps serving the control plane.
function publicSlug(req: IncomingMessage): { slug: string; claimed: boolean } | undefined {
  const host = hostOnly(req.headers.host);
  const domain = getSandbox()?.domain;
  if (domain && (host === domain || host.endsWith(`.${domain}`))) {
    return { slug: host === domain ? "" : host.slice(0, host.length - domain.length - 1), claimed: true };
  }
  if (host.endsWith(".localhost")) {
    const slug = host.slice(0, host.length - ".localhost".length);
    if (slug && viewBySlug(slug)) return { slug, claimed: true };
  }
  return undefined;
}

// Self-refreshing "app is starting" page: the iframe loads the instant the session is
// ready, but the dev server it fronts binds its port only after install/compile. A
// reset/502 would leave the browser on a dead error page that never retries.
const APP_STARTING_HTML =
  `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
  `<meta http-equiv="refresh" content="2"><title>Starting…</title>` +
  `<style>html,body{height:100%;margin:0}body{display:flex;align-items:center;justify-content:center;background:#0b0d10;color:#9aa4b2;` +
  `font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}.c{text-align:center}` +
  `.s{width:26px;height:26px;margin:0 auto 14px;border:3px solid #232a33;border-top-color:#5b8cff;border-radius:50%;animation:spin .8s linear infinite}` +
  `@keyframes spin{to{transform:rotate(360deg)}}.h{opacity:.6;font-size:12px;margin-top:6px}</style></head>` +
  `<body><div class="c"><div class="s"></div>Starting your app…<div class="h">Waiting for the dev server to come online — this retries automatically.</div></div></body></html>`;

function serveAppStarting(res: ServerResponse): void {
  if (res.headersSent) {
    try { res.end(); } catch { /* client gone */ }
    return;
  }
  res.writeHead(503, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "retry-after": "2" });
  res.end(APP_STARTING_HTML);
}

// The public plane owns its responses (selfHandleResponse): execd answers a refused
// app port with a 502 RESPONSE (not a connection error), and relaying it would leave
// the iframe on a dead "Bad Gateway" that never retries. A 502 upstream → the
// holding page instead, plus a throttled self-heal of the view's forwarder.
const publicProxy = httpProxy.createProxyServer({ ws: true, xfwd: true, changeOrigin: true, selfHandleResponse: true });
publicProxy.on("error", (_err, _req, res) => {
  const r = res as ServerResponse | Duplex | undefined;
  if (r && "writeHead" in r) serveAppStarting(r);
  else if (r && "destroy" in r) (r as Duplex).destroy();
});
publicProxy.on("proxyRes", (proxyRes, _req, res) => {
  const out = res as ServerResponse;
  if (proxyRes.statusCode === 502) {
    proxyRes.resume();
    serveAppStarting(out);
    return;
  }
  const h = { ...proxyRes.headers };
  delete h["x-frame-options"];
  out.writeHead(proxyRes.statusCode ?? 200, h);
  proxyRes.pipe(out);
});

// Self-heal: a 502 on the public plane can mean the view's forwarder is gone (a
// lifecycle race, a gate restart). Check + restart it, at most once per 10s per view.
const healing = new Map<string, number>();
function healForwarder(view: View): void {
  const last = healing.get(view.id) ?? 0;
  if (Date.now() - last < 10_000) return;
  healing.set(view.id, Date.now());
  void webForwarderAlive(view)
    .then((alive) => (alive ? undefined : startWebForwarder(view)))
    .catch(() => undefined);
}

// Returns true when the request was on a public-plane host (handled here, success or not).
export async function handlePublicWebRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const pub = publicSlug(req);
  if (!pub) return false;
  const view = pub.slug ? viewBySlug(pub.slug) : undefined;
  if (!view) {
    res.writeHead(404, { "content-type": "text/plain" }).end("unknown app");
    return true;
  }
  try {
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${req.url ?? "/"}`;
    res.once("finish", () => {
      if (res.statusCode === 503) healForwarder(view);
    });
    publicProxy.web(req, res, { target: `http://${t.host}` });
  } catch {
    targets.delete(`${view.sandboxId}:${view.port}`);
    serveAppStarting(res);
    healForwarder(view);
  }
  return true;
}

export async function handlePublicWebUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): Promise<boolean> {
  const pub = publicSlug(req);
  if (!pub) return false;
  const view = pub.slug ? viewBySlug(pub.slug) : undefined;
  if (!view) {
    socket.destroy();
    return true;
  }
  try {
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${req.url ?? "/"}`;
    publicProxy.ws(req, socket, head, { target: `http://${t.host}` });
  } catch {
    targets.delete(`${view.sandboxId}:${view.port}`);
    socket.destroy();
  }
  return true;
}
