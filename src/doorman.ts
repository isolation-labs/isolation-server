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
import { getView, isAnyDavPassword, isOurViewToken, verifyDavPassword, verifyViewToken, viewBySlug, type View } from "./views.js";
import { startWebForwarder, webForwarderAlive } from "./launch.js";
import { handleCodeView } from "./codeview.js";
import { handleAgentView } from "./agentview.js";
import { handleWebdav } from "./webdav.js";
import { ensureBridge } from "./acpview.js";

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

// The name a file client shows in its credential prompt and saves the mount under. The view's own
// label when it has one, so a member with two files views can tell the two keychain entries apart.
const davRealm = (view: View): string => (view.label ?? "Files").replace(/[^\x20-\x7e]/g, "").replace(/["\\]/g, "").slice(0, 60) || "Files";

export const viewIdFromUrl = (url: string | undefined): string | undefined => VIEW_RE.exec((url ?? "").split("?")[0])?.[1];

// The token an HTTP Basic credential carries, if any. A native file client (Finder, Explorer,
// GNOME Files) has NO other way to authenticate a mount: it cannot append a query parameter to the
// requests it generates itself and it will not carry a bearer. The token is taken from the password
// — where a client stores it in the OS keychain and where the username is free to be a label — and
// from the username as a fallback, for clients that send a password-less credential.
export function basicToken(auth: string | undefined): string | undefined {
  if (!auth || !/^basic /i.test(auth)) return undefined;
  let decoded: string;
  try {
    decoded = Buffer.from(auth.slice(6).trim(), "base64").toString("utf8");
  } catch {
    return undefined;
  }
  const colon = decoded.indexOf(":");
  if (colon < 0) return decoded || undefined;
  return decoded.slice(colon + 1) || decoded.slice(0, colon) || undefined;
}

// EVERY credential the request carries, in preference order — not the first one present. The
// difference matters because an Authorization header is not necessarily ours: a view app inside the
// sandbox may run its OWN basic auth, and once a browser has been prompted by it, it attaches that
// credential to every request on this origin. Returning it and stopping would make the doorman
// reject a request whose cookie was valid all along, locking the view out until the browser's saved
// password is cleared. Each candidate is simply tried.
export function tokensFromRequest(req: IncomingMessage): string[] {
  const out: string[] = [];
  const u = new URL(req.url ?? "/", "http://x");
  const q = u.searchParams.get("token");
  if (q) out.push(q);
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) out.push(auth.slice(7));
  const basic = basicToken(auth);
  if (basic) out.push(basic);
  const cookies = req.headers.cookie ?? "";
  for (const c of cookies.split(";")) {
    const [k, ...rest] = c.trim().split("=");
    if (k !== "isolation-server_token") continue;
    const raw = rest.join("=");
    try {
      out.push(decodeURIComponent(raw));
    } catch {
      out.push(raw); // malformed escape — judge the raw form, which is what we would have compared anyway
    }
  }
  return out;
}

// `isDav` widens the accepted credentials by exactly one: the view's stable mount password
// (views.ts davPassword), which is deliberately confined to that view's own /dav path. It is the
// one credential here that never expires, so it must not become a way in anywhere else.
const authorized = (req: IncomingMessage, viewId: string, isDav = false): { ok: boolean; queryToken?: string } => {
  const ok = tokensFromRequest(req).some((t) => tokenMatches(t) || verifyViewToken(t, viewId) || (isDav && verifyDavPassword(t, viewId)));
  const u = new URL(req.url ?? "/", "http://x");
  // Only a `?token=` that is ITSELF valid may be promoted to the view cookie below. Now that every
  // credential on the request is tried, `ok` can come from the cookie while the query carries a
  // stale or hostile value — promoting that would overwrite a working cookie with a dead one and
  // lock the view out of its own frame. The mount password is deliberately not promotable either:
  // it never expires, and a long-lived cookie is not where a credential like that belongs.
  const q = u.searchParams.get("token") ?? undefined;
  return { ok, queryToken: q && (tokenMatches(q) || verifyViewToken(q, viewId)) ? q : undefined };
};

// Our own credentials must NEVER be handed to a sandbox: the app behind a view — a dev server, a
// cloned repo's code, whatever the agent wrote — is not trusted with the token that drives this
// server's whole control plane. It does not normally ride this far, but the cloud's control proxy
// adds `Authorization: Bearer <master token>` to every /api/servers/<id>/p/* call while forwarding
// the caller's other headers verbatim — and `x-forwarded-host` is one of those, so a caller can
// steer such a request onto the public plane. Strip OURS only: a view app's own Bearer or cookie
// auth is its business and passes through untouched.
export function stripOurCredentials(req: IncomingMessage): void {
  const auth = req.headers.authorization;
  // "Ours" is judged WITHOUT pinning to the view being proxied. A credential of ours is ours
  // wherever it turns up, and a sandbox app is exactly the party that must not see one — while the
  // request that carries it is not necessarily the view it belongs to (see the Basic note below).
  // Nothing a sandbox could invent passes these checks: each is an HMAC under this server's token.
  const ours = (t: string): boolean => tokenMatches(t) || isOurViewToken(t) || isAnyDavPassword(t);
  if (auth?.startsWith("Bearer ") && ours(auth.slice(7))) delete req.headers.authorization;
  // The same rule for the Basic form a mount client sends: a view app must never be handed the
  // credential that authenticated the request to US. An app's OWN basic auth is left alone.
  //
  // The mount password is stripped too, even though it does not authorize a proxied path: a request
  // can be authorized by its query token and STILL carry one in a Basic header, and that password
  // never expires — leaking it to whatever the sandbox is serving would hand out the folder for the
  // life of the view. And unlike the view cookie (`Path=/v/<id>`), HTTP Basic has NO path scoping,
  // so the view it arrives on is NOT necessarily the view it opens — hence `isAnyDavPassword`.
  const basic = basicToken(auth);
  if (basic && ours(basic)) delete req.headers.authorization;
  const cookie = req.headers.cookie;
  if (!cookie) return;
  const parts = cookie.split(";");
  const kept = parts.filter((c) => {
    const [k, ...rest] = c.trim().split("=");
    if (k !== "isolation-server_token") return true;
    const raw = rest.join("=");
    let v = raw;
    try {
      v = decodeURIComponent(raw);
    } catch {
      /* malformed escape — judge the raw form, which is what we would have compared anyway */
    }
    return !tokenMatches(v);
  });
  if (kept.length === parts.length) return;
  if (kept.length) req.headers.cookie = kept.join(";");
  else delete req.headers.cookie;
}

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
  const rest = m[2] || "/";
  const isDav = view.type === "directory" && (rest === "/dav" || rest.startsWith("/dav/"));
  const { ok, queryToken } = authorized(req, viewId, isDav);
  if (!ok) {
    // A file client has no login page: it authenticates only after a Basic challenge, and it needs
    // the realm to label the keychain entry it saves the mount's token under.
    if (isDav) res.setHeader("WWW-Authenticate", `Basic realm="${davRealm(view)}", charset="UTF-8"`);
    res.writeHead(401, { "Content-Type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
    return true;
  }
  // Promote a valid query token to a view-scoped cookie for the follow-up requests.
  if (queryToken) {
    res.setHeader("Set-Cookie", `isolation-server_token=${encodeURIComponent(queryToken)}; Path=/v/${viewId}; HttpOnly; SameSite=None; Secure`);
  }
  // Code and agent views are first-party (PLAN V1/§5d): the doorman serves the app (and the
  // code view's API) itself. An agent view's WebSocket is the one thing proxied — to the
  // in-sandbox ACP bridge (handleViewUpgrade).
  if (view.type === "code") {
    await handleCodeView(req, res, view, rest);
    return true;
  }
  if (view.type === "agent") {
    await handleAgentView(req, res, view, rest);
    return true;
  }
  // A files view's external door: `/v/<id>/dav/*` is WebDAV, served here over execd, so the same
  // view a browser renders through filebrowser can be MOUNTED as a drive with nothing installed
  // (webdav.ts). The rest of the view path stays filebrowser's.
  if (isDav) {
    const pathname = (req.url ?? "/").split("?")[0];
    // The prefix the mount is addressed at, taken from THIS request rather than assumed, so hrefs
    // stay followable when something in front adds a path prefix of its own.
    const prefix = `${pathname.slice(0, pathname.length - rest.length)}/dav`;
    await handleWebdav(req, res, view, rest.slice("/dav".length), prefix);
    return true;
  }
  try {
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${viewPath(view, req.url, viewId)}`;
    stripOurCredentials(req);
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
  if (!viewId || !view || view.type === "code" || !view.port || !authorized(req, viewId).ok) {
    // Code views are doorman-served static pages + REST — no WebSocket to upgrade to.
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }
  try {
    // An agent view's bridge can be gone (a crash, a sandbox restart, a lifecycle race), and
    // execd answers a dead port with a 502 RESPONSE the proxy would relay silently — so the
    // bridge is checked (and restarted, one attempt at a time per view) BEFORE the upgrade.
    // The bridge reloads the harness session from the thread file, so nothing is lost.
    if (view.type === "agent" && !(await ensureBridge(view))) {
      socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
      socket.destroy();
      return;
    }
    const t = await resolveTarget(view.sandboxId, view.port);
    req.url = `${t.basePath}${viewPath(view, req.url, viewId)}`;
    stripOurCredentials(req);
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
// design (the slug's random tail is the secret — views.ts newWebSlug) and it claims sandbox hosts
// whole: the token-gated API and /v/ views are never reachable on these hostnames.

const hostOnly = (h: string | undefined): string => (h ?? "").split(":")[0].trim().toLowerCase();

// The public-plane claim for ONE hostname, or undefined when that host is not ours.
// A configured sandbox domain claims ALL its subdomains (unknown slug → 404, never the
// API). `.localhost` claims only labels that match a live web view, so plain
// `localhost` keeps serving the control plane.
function claimFor(host: string): { slug: string; claimed: boolean } | undefined {
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

// The hostname a proxied request was addressed to, as the BROWSER wrote it.
//
// When the cloud's Worker proxies a public web preview to us over the private tunnel it cannot
// rely on forwarding the real Host: `Host` is a forbidden header for fetch(), so a `headers.set`
// can be silently dropped and we would see the address it dialled (127.0.0.1:8090) instead of
// `<slug>.<domain>`. The Worker sends `x-forwarded-host` for exactly this. It is a LIST header and
// arrives as a comma-joined string (or repeated); the first entry is the original client's.
const forwardedHost = (req: IncomingMessage): string => {
  const raw = req.headers["x-forwarded-host"];
  return hostOnly((Array.isArray(raw) ? raw[0] : raw)?.split(",")[0]);
};

// The slug when this request belongs to the public plane; undefined otherwise.
function publicSlug(req: IncomingMessage): { slug: string; claimed: boolean } | undefined {
  // The real Host wins whenever it is ours. It is the one name a browser cannot forge, so a
  // request actually addressed to `<slug>.<domain>` stays claimed WHOLE — the token-gated API and
  // /v/ are never reachable there — no matter what a page inside the sandbox puts on a
  // same-origin fetch (`x-forwarded-host` is NOT a forbidden header, so sandbox JS can set it).
  const direct = claimFor(hostOnly(req.headers.host));
  if (direct) return direct;
  // A forwarded host, by contrast, claims ONLY a label that names a live web view. The cloud dials
  // the VIEW plane at the loopback address behind the tunnel on purpose (preview.ts serveView: the public
  // plane would otherwise 404 it) while still forwarding the browser's `v--<serverId>.<domain>`
  // — so a label that is not a preview slug MUST fall through to `/v/` and its per-view token
  // gate rather than being answered with "unknown app".
  const fwd = claimFor(forwardedHost(req));
  return fwd?.slug && viewBySlug(fwd.slug) ? fwd : undefined;
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
    stripOurCredentials(req);
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
    stripOurCredentials(req);
    publicProxy.ws(req, socket, head, { target: `http://${t.host}` });
  } catch {
    targets.delete(`${view.sandboxId}:${view.port}`);
    socket.destroy();
  }
  return true;
}
