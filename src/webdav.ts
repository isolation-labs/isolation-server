// WebDAV for the files view — "open externally" without anything extra in the sandbox.
//
// The old daemon mounted files by installing samba in every sandbox. Under OpenSandbox that is not
// an option (execd plus two published ports is the whole surface), and terminating SMB on the
// bastion would mean FUSE mounts there plus port 445, which most corporate networks block outbound.
// WebDAV is plain HTTPS, so it rides the SAME path a web view already takes — doorman → tunnel →
// Worker — and macOS Finder, Windows Explorer, GNOME Files and KDE all mount it with nothing
// installed. Nothing new runs inside the sandbox: every operation here is an execd call, exactly
// like the code view (codeview.ts) does for the editor.
//
// Class 2 (LOCK/UNLOCK) is implemented because macOS mounts a class-1 server READ-ONLY. The locks
// are advisory: one member owns a workspace, so a lock that refuses another writer would only ever
// get in the way of that member's own agent.
//
// Auth happened in the doorman before we are called (view token, cookie, or HTTP Basic — the only
// credential channel a native file client has).
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { downloadFile, run, UploadTooLarge, writeFileStream } from "./execd.js";
import type { View } from "./views.js";

const WORKSPACE = "/workspace";

// A PUT ceiling. Cloudflare rejects request bodies over 100MB on Pro plans anyway (500MB on
// Business), so a cloud-server mount cannot exceed that whatever we allow; the cap exists so a
// connected server — reached directly on loopback, with no proxy in between — has one too.
const MAX_PUT_BYTES = Number(process.env.ISOLATION_DAV_MAX_BYTES ?? 100 * 1024 * 1024);

const DAV_METHODS = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

// Files the Finder and Explorer scatter over any share they touch. They are pure client bookkeeping
// (icon positions, resource forks, thumbnail caches) and a workspace is a GIT REPO: left alone they
// land in `git status`, get committed by an agent that was told to commit everything, and travel to
// everyone else. Writes to them are ACCEPTED and dropped, so the client believes it succeeded and
// nothing reaches the disk.
const DROPPED = [/^\.DS_Store$/, /^\._/, /^\.Spotlight-V100$/, /^\.TemporaryItems$/, /^\.fseventsd$/, /^\.apdisk$/, /^Thumbs\.db$/i, /^desktop\.ini$/i];
const isDropped = (rel: string): boolean => {
  const name = rel.slice(rel.lastIndexOf("/") + 1);
  return DROPPED.some((re) => re.test(name));
};

// ── paths ────────────────────────────────────────────────────────────────────────────────────────

/**
 * A DAV request path (percent-encoded, `/`-separated) → a workspace-relative path, or undefined
 * when it escapes.
 *
 * Deliberately more permissive than codeview's safeRelPath: a real filesystem holds names with
 * spaces, backslashes and every kind of unicode, and a files view that cannot show them is broken.
 * What is refused is what could leave the root — `.`, `..`, empty segments, absolute paths — plus
 * control bytes, which no legitimate name has and which would let a name break out of the shell
 * variables the exec paths below rely on.
 */
export function davRelPath(raw: string): string | undefined {
  const trimmed = raw.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!trimmed) return "";
  if (trimmed.length > 2048) return undefined;
  const out: string[] = [];
  for (const seg of trimmed.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      return undefined; // malformed %-escape
    }
    if (!decoded || decoded === "." || decoded === "..") return undefined;
    // A decoded segment that still holds a separator is the traversal that survives splitting
    // first: `..%2f..%2fetc` is ONE segment until it is decoded, and it is neither "." nor ".." —
    // it becomes `../../etc` inside a path this function has already blessed. No filename on any
    // POSIX filesystem contains a slash, so refusing one costs nothing and closes the hole.
    if (decoded.includes("/")) return undefined;
    if ([...decoded].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) return undefined;
    out.push(decoded);
  }
  return out.join("/");
}

// The sandbox path a view's DAV root maps onto: /workspace, or the subtree the view was scoped to.
const rootOf = (view: View): string => (view.dir ? `${WORKSPACE}/${view.dir}` : WORKSPACE);
const absOf = (view: View, rel: string): string => (rel ? `${rootOf(view)}/${rel}` : rootOf(view));

// An href for the multistatus body: the mount's own prefix plus the encoded path. Built from the
// prefix the REQUEST arrived on, so a mount reached through a proxy that adds a path prefix still
// gets hrefs its client can follow.
const href = (prefix: string, rel: string, isDir: boolean): string => {
  const encoded = rel ? `/${rel.split("/").map(encodeURIComponent).join("/")}` : "";
  return `${prefix}${encoded}${isDir ? "/" : ""}` || "/";
};

// ── entries ──────────────────────────────────────────────────────────────────────────────────────

interface Entry {
  rel: string; // workspace-relative, "" for the root
  name: string;
  isDir: boolean;
  size: number;
  mtime: number; // unix seconds
}

interface Listing {
  self: Entry;
  children: Entry[];
  quota?: { available: number; used: number };
}

/**
 * One execd round trip for a PROPFIND: the resource itself, its children when depth is 1, and the
 * filesystem's free space.
 *
 * `stat -L` DEREFERENCES symlinks on purpose. A symlink inside the workspace is content the session
 * itself created, and the alternative — showing it as a zero-byte file whose GET quietly returns the
 * target's bytes (execd's download follows links) — is the confusing option, not the safe one. A
 * broken link fails its stat and is simply skipped.
 *
 * The quota matters more than it looks: macOS checks `quota-available-bytes` before a copy and
 * refuses one it thinks will not fit, so a server that omits it or reports zero mounts read-only in
 * practice.
 */
async function statTree(sandboxId: string, abs: string, depth: 0 | 1): Promise<Listing | undefined> {
  const cmd =
    `stat -L -c 'S %f %s %Y %n' "$ISO_P" 2>/dev/null || { exit 1; }; ` +
    `if [ "$ISO_DEPTH" = "1" ] && [ -d "$ISO_P" ]; then ` +
    `find "$ISO_P" -mindepth 1 -maxdepth 1 -exec stat -L -c 'S %f %s %Y %n' {} + 2>/dev/null; fi; ` +
    // printf, not print: awk's default output format renders a number this large in scientific
    // notation ("4.98458e+10"), which loses the low digits and is not what a byte count should be.
    `df -P -k "$ISO_P" 2>/dev/null | awk 'NR==2 {printf "DF %.0f %.0f\\n", $4*1024, $3*1024}'; exit 0`;
  const r = await run(sandboxId, cmd, { envs: { ISO_P: abs, ISO_DEPTH: String(depth) }, timeoutMs: 30_000 });
  if (!r.ok) return undefined;

  let self: Entry | undefined;
  const children: Entry[] = [];
  let quota: Listing["quota"];
  for (const line of r.stdout.split("\n")) {
    if (line.startsWith("DF ")) {
      const [, a, u] = line.split(" ");
      const available = Number(a);
      const used = Number(u);
      if (Number.isFinite(available) && Number.isFinite(used)) quota = { available, used };
      continue;
    }
    if (!line.startsWith("S ")) continue;
    // `S <mode-hex> <size> <mtime> <path>` — the path is last because it is the only field that can
    // contain a space.
    const m = /^S ([0-9a-fA-F]+) (\d+) (\d+) (.*)$/.exec(line);
    if (!m) continue;
    const isDir = (parseInt(m[1], 16) & 0xf000) === 0x4000;
    const path = m[4];
    const e: Entry = { rel: "", name: "", isDir, size: Number(m[2]), mtime: Number(m[3]) };
    if (path === abs) {
      self = { ...e, name: abs.slice(abs.lastIndexOf("/") + 1) };
    } else if (path.startsWith(`${abs}/`)) {
      const name = path.slice(abs.length + 1);
      if (name.includes("/")) continue; // maxdepth 1 means this cannot happen; belt and braces
      children.push({ ...e, name });
    }
  }
  if (!self) return undefined;
  return { self, children, quota };
}

// ── XML ──────────────────────────────────────────────────────────────────────────────────────────

// Attribute contexts (namespace URIs) — quotes escaped, because they delimit the attribute.
const xmlEscape = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
// Element TEXT — quotes left alone. `&quot;` inside text is legal XML and every real client parses
// it, but an ETag is quoted by definition, and mod_dav and every server clients were written
// against emit `<D:getetag>"abc"</D:getetag>`. Matching them costs nothing and rules out a whole
// class of client that pattern-matches the response instead of parsing it.
const xmlText = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const httpDate = (unixSeconds: number): string => new Date(unixSeconds * 1000).toUTCString();
const isoDate = (unixSeconds: number): string => new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const etagOf = (e: Entry): string => `"${e.mtime.toString(16)}-${e.size.toString(16)}"`;

interface PropRef {
  ns: string;
  name: string;
}

interface PropfindRequest {
  mode: "allprop" | "propname" | "prop";
  props: PropRef[];
}

/**
 * Parse a PROPFIND body without pulling in an XML parser.
 *
 * The grammar we care about is tiny — `<allprop/>`, `<propname/>`, or a `<prop>` element whose
 * children name the properties — but the namespaces are not optional: a client that asks for
 * `http://apple.com/ns:...` must get those back in a 404 propstat under THEIR namespace, not under
 * DAV:, or the client treats the whole response as malformed. So prefixes are resolved against the
 * xmlns declarations actually present in the document.
 *
 * An empty or unparseable body means allprop (RFC 4918 §9.1: an empty body is treated as allprop),
 * which is also the forgiving thing to do.
 */
export function parsePropfind(body: string): PropfindRequest {
  const text = body.replace(/<!--[\s\S]*?-->/g, "");
  if (!text.trim()) return { mode: "allprop", props: [] };
  if (/<[\w.-]*:?propname\s*\/?>/i.test(text)) return { mode: "propname", props: [] };

  // Prefix → namespace URI, from every xmlns declaration in the document (they are almost always on
  // the root element, and a nested redeclaration of the same prefix is not something clients emit).
  const nsByPrefix = new Map<string, string>([["", "DAV:"]]);
  for (const m of text.matchAll(/xmlns(?::([\w.-]+))?\s*=\s*"([^"]*)"/g)) nsByPrefix.set(m[1] ?? "", m[2]);

  const propBlock = /<([\w.-]*:?)prop(?:\s[^>]*)?>([\s\S]*?)<\/\1prop\s*>/i.exec(text);
  if (!propBlock) return { mode: "allprop", props: [] };

  const props: PropRef[] = [];
  const seen = new Set<string>();
  for (const m of propBlock[2].matchAll(/<([\w.-]+:)?([\w.-]+)(?:\s[^>]*?)?\s*\/?>/g)) {
    const prefix = (m[1] ?? "").replace(/:$/, "");
    const name = m[2];
    const ns = nsByPrefix.get(prefix) ?? "DAV:";
    const key = `${ns}\u0000${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    props.push({ ns, name });
  }
  return props.length ? { mode: "prop", props } : { mode: "allprop", props: [] };
}

// Every property this server can answer. `getcontenttype` and `getcontentlength` are omitted for
// collections on purpose — RFC 4918 says they do not apply, and Finder is happier without them.
const LIVE_PROPS = [
  "resourcetype",
  "displayname",
  "getlastmodified",
  "creationdate",
  "getetag",
  "getcontentlength",
  "getcontenttype",
  "supportedlock",
  "lockdiscovery",
  "quota-available-bytes",
  "quota-used-bytes",
] as const;

function propValue(name: string, e: Entry, quota: Listing["quota"], locks: ActiveLock[]): string | undefined {
  switch (name) {
    case "resourcetype":
      return e.isDir ? "<D:collection/>" : "";
    case "displayname":
      return xmlText(e.name);
    case "getlastmodified":
      return xmlText(httpDate(e.mtime));
    case "creationdate":
      return xmlText(isoDate(e.mtime));
    case "getetag":
      return xmlText(etagOf(e));
    case "getcontentlength":
      return e.isDir ? undefined : String(e.size);
    case "getcontenttype":
      return e.isDir ? undefined : xmlText(contentType(e.name));
    case "supportedlock":
      return `<D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>` +
        `<D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>`;
    case "lockdiscovery":
      return locks.map((l) => activeLockXml(l)).join("");
    case "quota-available-bytes":
      return quota ? String(quota.available) : undefined;
    case "quota-used-bytes":
      return quota ? String(quota.used) : undefined;
    default:
      return undefined;
  }
}

// One `<D:response>`: the found properties in a 200 propstat, the asked-for-but-unknown ones in a
// 404 propstat. Clients rely on that split — a missing property silently omitted reads as "the
// server is broken", while an explicit 404 reads as "not supported here".
function responseXml(hrefStr: string, e: Entry, req: PropfindRequest, quota: Listing["quota"], locks: ActiveLock[], nsAlias: (ns: string) => string): string {
  const found: string[] = [];
  const missing: string[] = [];

  if (req.mode === "propname") {
    for (const name of LIVE_PROPS) if (propValue(name, e, quota, locks) !== undefined) found.push(`<D:${name}/>`);
  } else {
    const wanted: PropRef[] = req.mode === "allprop" ? LIVE_PROPS.map((name) => ({ ns: "DAV:", name })) : req.props;
    for (const p of wanted) {
      const value = p.ns === "DAV:" ? propValue(p.name, e, quota, locks) : undefined;
      if (value === undefined) {
        // allprop asks for "everything you have", so a property that does not apply to this resource
        // (a collection's content length) is simply absent rather than a 404 the client must read.
        if (req.mode !== "allprop") missing.push(`<${nsAlias(p.ns)}${p.name}/>`);
      } else {
        found.push(value === "" ? `<D:${p.name}/>` : `<D:${p.name}>${value}</D:${p.name}>`);
      }
    }
  }

  let out = `<D:response><D:href>${xmlText(hrefStr)}</D:href>`;
  out += `<D:propstat><D:prop>${found.join("")}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`;
  if (missing.length) out += `<D:propstat><D:prop>${missing.join("")}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>`;
  return `${out}</D:response>`;
}

// ── locks ────────────────────────────────────────────────────────────────────────────────────────

interface ActiveLock {
  token: string; // opaquelocktoken:<uuid>
  rel: string;
  depth: "0" | "infinity";
  exclusive: boolean;
  owner: string; // the client's <owner> content, echoed back verbatim
  expires: number; // epoch ms
}

// Locks are per (sandbox, path) and live only in this process: a restart drops them, and a client
// that finds its token gone simply re-locks. Nothing durable depends on them — see the header note
// on why they are advisory.
const locksBySandbox = new Map<string, Map<string, ActiveLock>>();

function liveLocks(sandboxId: string, rel: string): ActiveLock[] {
  const table = locksBySandbox.get(sandboxId);
  if (!table) return [];
  const now = Date.now();
  const hit = table.get(rel);
  if (!hit) return [];
  if (hit.expires <= now) {
    table.delete(rel);
    return [];
  }
  return [hit];
}

// Drop expired entries so a long-lived server does not accumulate them (a client that never
// UNLOCKs — a laptop that slept, a force-unmount — is the normal case, not the exception).
function reapLocks(): void {
  const now = Date.now();
  for (const [sandboxId, table] of locksBySandbox) {
    for (const [rel, l] of table) if (l.expires <= now) table.delete(rel);
    if (!table.size) locksBySandbox.delete(sandboxId);
  }
}

export function dropLocksForSandbox(sandboxId: string): void {
  locksBySandbox.delete(sandboxId);
}

const activeLockXml = (l: ActiveLock): string =>
  `<D:activelock><D:locktype><D:write/></D:locktype>` +
  `<D:lockscope>${l.exclusive ? "<D:exclusive/>" : "<D:shared/>"}</D:lockscope>` +
  `<D:depth>${l.depth}</D:depth>` +
  (l.owner ? `<D:owner>${l.owner}</D:owner>` : "") +
  `<D:timeout>Second-${Math.max(1, Math.round((l.expires - Date.now()) / 1000))}</D:timeout>` +
  `<D:locktoken><D:href>${xmlText(l.token)}</D:href></D:locktoken></D:activelock>`;

// `Timeout: Second-600, Infinite` — take the first numeric value, clamped. Infinite is not honoured:
// a lock nothing can ever release is a leak, and every client refreshes.
function lockTimeout(header: string | undefined): number {
  const m = /Second-(\d+)/i.exec(header ?? "");
  const secs = m ? Number(m[1]) : 3600;
  return Math.min(Math.max(secs, 60), 24 * 3600) * 1000;
}

// The lock tokens an `If:` header names, in submission order. The full RFC 4918 §10.4 grammar is
// a tagged/untagged list of conditions; every token in it appears as `<...>` inside `(...)`, and
// that is all a refresh or a write check needs.
export function ifTokens(header: string | undefined): string[] {
  if (!header) return [];
  return [...header.matchAll(/\(([^)]*)\)/g)].flatMap((m) => [...m[1].matchAll(/<((?:opaquelocktoken|urn):[^>]+)>/g)].map((t) => t[1]));
}

// ── content types ────────────────────────────────────────────────────────────────────────────────

const TYPES: Record<string, string> = {
  ".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".json": "application/json",
  ".js": "text/javascript", ".mjs": "text/javascript", ".ts": "text/plain; charset=utf-8",
  ".tsx": "text/plain; charset=utf-8", ".jsx": "text/plain; charset=utf-8", ".css": "text/css",
  ".html": "text/html", ".htm": "text/html", ".xml": "application/xml", ".yml": "text/yaml", ".yaml": "text/yaml",
  ".csv": "text/csv", ".pdf": "application/pdf", ".zip": "application/zip", ".gz": "application/gzip",
  ".tar": "application/x-tar", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp", ".ico": "image/x-icon",
  ".avif": "image/avif", ".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
  ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg", ".flac": "audio/flac",
  ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
};
const contentType = (name: string): string => {
  const dot = name.lastIndexOf(".");
  return (dot > 0 ? TYPES[name.slice(dot).toLowerCase()] : undefined) ?? "application/octet-stream";
};

// ── responses ────────────────────────────────────────────────────────────────────────────────────

const plain = (res: ServerResponse, status: number, text = ""): void => {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
};

const xml = (res: ServerResponse, status: number, body: string, extra: Record<string, string> = {}): void => {
  const payload = Buffer.from(`<?xml version="1.0" encoding="utf-8"?>\n${body}`, "utf8");
  res.writeHead(status, { "Content-Type": "application/xml; charset=utf-8", "Content-Length": payload.length, ...extra });
  res.end(payload);
};

// Read a request body with a hard cap, for the small XML documents DAV control methods carry.
async function readBody(req: IncomingMessage, limit = 256 * 1024): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    total += (c as Buffer).length;
    if (total > limit) return undefined;
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// ── the handler ──────────────────────────────────────────────────────────────────────────────────

/**
 * Serve one WebDAV request for a files view.
 *
 * `rest` is the path under the mount root (`""` or `/a/b`, still percent-encoded) and `prefix` is
 * the absolute path the mount is addressed at, which is what every href in a multistatus body must
 * be built from.
 */
export async function handleWebdav(req: IncomingMessage, res: ServerResponse, view: View, rest: string, prefix: string): Promise<void> {
  const method = (req.method ?? "GET").toUpperCase();
  const rel = davRelPath(rest);
  if (rel === undefined) return plain(res, 400, "bad path");
  reapLocks();

  // Advertise class 2 on EVERY response, not just OPTIONS: macOS re-checks the DAV header on
  // arbitrary responses and downgrades the mount to read-only when it goes missing.
  res.setHeader("DAV", "1, 2");
  res.setHeader("MS-Author-Via", "DAV");

  try {
    switch (method) {
      case "OPTIONS":
        res.writeHead(200, { Allow: DAV_METHODS, "Content-Length": "0", "Accept-Ranges": "bytes" });
        return void res.end();
      case "PROPFIND":
        return await propfind(req, res, view, rel, prefix);
      case "PROPPATCH":
        return await proppatch(req, res, view, rel, prefix);
      case "GET":
      case "HEAD":
        return await getFile(req, res, view, rel, method === "HEAD");
      case "PUT":
        return await putFile(req, res, view, rel);
      case "DELETE":
        return await deleteEntry(res, view, rel);
      case "MKCOL":
        return await mkcol(req, res, view, rel);
      case "MOVE":
      case "COPY":
        return await moveOrCopy(req, res, view, rel, prefix, method === "MOVE");
      case "LOCK":
        return await lock(req, res, view, rel, prefix);
      case "UNLOCK":
        return unlock(req, res, view, rel);
      default:
        res.writeHead(405, { Allow: DAV_METHODS, "Content-Length": "0" });
        return void res.end();
    }
  } catch (e) {
    // A GET that fails MID-BODY (the sandbox dies under a large read) has already sent its headers,
    // and writing a status onto that throws ERR_HTTP_HEADERS_SENT — which would replace a truncated
    // download with a rejected promise and a response nothing ever ends, one hung socket per
    // failure. Destroy the connection instead: a torn-off body is what the client must see anyway.
    if (res.headersSent) return void res.destroy();
    return plain(res, 502, String((e as Error)?.message ?? e).slice(0, 300));
  }
}

async function propfind(req: IncomingMessage, res: ServerResponse, view: View, rel: string, prefix: string): Promise<void> {
  const depthHeader = String(req.headers.depth ?? "1").trim().toLowerCase();
  if (depthHeader === "infinity") {
    // Refusing infinity is explicitly allowed (RFC 4918 §9.1) and is the only sane answer over a
    // remote filesystem: one `find` over a node_modules tree would hang the mount. No client we
    // care about asks for it.
    return xml(res, 403, `<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`);
  }
  const depth: 0 | 1 = depthHeader === "0" ? 0 : 1;

  const body = await readBody(req);
  const request = parsePropfind(body ?? "");
  if (isDropped(rel)) return plain(res, 404, "not found");

  const listing = await statTree(view.sandboxId, absOf(view, rel), depth);
  if (!listing) return plain(res, 404, "not found");

  // Foreign namespaces get a generated alias declared on the root element; DAV: keeps the `D`
  // prefix every client expects to see.
  const aliases = new Map<string, string>();
  const nsAlias = (ns: string): string => {
    if (ns === "DAV:") return "D:";
    let a = aliases.get(ns);
    if (!a) {
      a = `n${aliases.size + 1}`;
      aliases.set(ns, a);
    }
    return `${a}:`;
  };

  const bodies: string[] = [];
  const self = { ...listing.self, name: rel ? rel.slice(rel.lastIndexOf("/") + 1) : (view.label ?? "workspace") };
  bodies.push(responseXml(href(prefix, rel, self.isDir), self, request, listing.quota, liveLocks(view.sandboxId, rel), nsAlias));
  for (const child of listing.children) {
    const childRel = rel ? `${rel}/${child.name}` : child.name;
    if (isDropped(childRel)) continue;
    bodies.push(responseXml(href(prefix, childRel, child.isDir), child, request, listing.quota, liveLocks(view.sandboxId, childRel), nsAlias));
  }

  const decls = [...aliases].map(([ns, a]) => ` xmlns:${a}="${xmlEscape(ns)}"`).join("");
  xml(res, 207, `<D:multistatus xmlns:D="DAV:"${decls}>${bodies.join("")}</D:multistatus>`);
}

/**
 * PROPPATCH: accept, store nothing, report success.
 *
 * Dead properties would have to live somewhere, and the only honest place is inside the workspace —
 * a hidden metadata file in a git repo the member also edits from an editor and an agent. Refusing
 * instead is not an option: Finder PROPPATCHes on essentially every file it writes (it sets Win32
 * timestamps) and treats a failure as a failed copy, so a strict server cannot be written to at all.
 * Reporting 200 for properties we drop is what every filesystem-backed DAV server does.
 */
async function proppatch(req: IncomingMessage, res: ServerResponse, view: View, rel: string, prefix: string): Promise<void> {
  const body = (await readBody(req)) ?? "";
  const listing = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (!listing) return plain(res, 404, "not found");

  const nsByPrefix = new Map<string, string>([["", "DAV:"]]);
  for (const m of body.matchAll(/xmlns(?::([\w.-]+))?\s*=\s*"([^"]*)"/g)) nsByPrefix.set(m[1] ?? "", m[2]);
  const aliases = new Map<string, string>();
  const names: string[] = [];
  for (const block of body.matchAll(/<([\w.-]*:?)prop(?:\s[^>]*)?>([\s\S]*?)<\/\1prop\s*>/gi)) {
    for (const m of block[2].matchAll(/<([\w.-]+:)?([\w.-]+)(?:\s[^>]*?)?\s*\/?>/g)) {
      const p = (m[1] ?? "").replace(/:$/, "");
      const ns = nsByPrefix.get(p) ?? "DAV:";
      if (ns === "DAV:") {
        names.push(`<D:${m[2]}/>`);
      } else {
        let a = aliases.get(ns);
        if (!a) {
          a = `n${aliases.size + 1}`;
          aliases.set(ns, a);
        }
        names.push(`<${a}:${m[2]}/>`);
      }
    }
  }
  const decls = [...aliases].map(([ns, a]) => ` xmlns:${a}="${xmlEscape(ns)}"`).join("");
  xml(
    res,
    207,
    `<D:multistatus xmlns:D="DAV:"${decls}><D:response><D:href>${xmlText(href(prefix, rel, listing.self.isDir))}</D:href>` +
      `<D:propstat><D:prop>${names.join("")}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`,
  );
}

async function getFile(req: IncomingMessage, res: ServerResponse, view: View, rel: string, headOnly: boolean): Promise<void> {
  if (isDropped(rel)) return plain(res, 404, "not found");
  const listing = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (!listing) return plain(res, 404, "not found");
  const e = listing.self;

  if (e.isDir) {
    // A collection GET is not part of the mount path (Finder never issues one), but a browser or a
    // curl pointed at the mount will. Plain text, never HTML: these are names the sandbox chose,
    // and this origin serves them without a chance to become a document that runs.
    const body = listing.children.map((c) => `${c.name}${c.isDir ? "/" : ""}`).sort().join("\n");
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Length": Buffer.byteLength(body),
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "X-Content-Type-Options": "nosniff",
    });
    return void res.end(headOnly ? undefined : body);
  }

  const headers: Record<string, string> = {
    "Content-Type": contentType(e.name),
    "Last-Modified": httpDate(e.mtime),
    ETag: etagOf(e),
    "Accept-Ranges": "bytes",
    "Cache-Control": "no-store",
    // Workspace bytes on the data-plane origin: a top-level navigation here must never execute (an
    // SVG or an HTML file the agent wrote would otherwise run with the view's cookie). Same posture
    // as the code view's file endpoint.
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "X-Content-Type-Options": "nosniff",
  };

  // A conditional GET the client already has the answer to — Finder revalidates constantly.
  const inm = req.headers["if-none-match"];
  if (typeof inm === "string" && inm.split(",").some((t) => t.trim() === etagOf(e))) {
    res.writeHead(304, headers);
    return void res.end();
  }

  const range = parseRange(req.headers.range, e.size);
  if (range === "unsatisfiable") {
    res.writeHead(416, { "Content-Range": `bytes */${e.size}` });
    return void res.end();
  }

  if (headOnly) {
    res.writeHead(200, { ...headers, "Content-Length": String(e.size) });
    return void res.end();
  }

  const upstream = await downloadFile(view.sandboxId, absOf(view, rel), range ? { start: range.start, end: range.end } : undefined);
  if (!upstream.ok || !upstream.body) return plain(res, upstream.status === 404 ? 404 : 502, `read failed (HTTP ${upstream.status})`);

  // execd may or may not honour Range. When it does the body is already the slice; when it does
  // not (a 200 for a ranged ask) the slice is taken here, so the client always gets the bytes it
  // asked for and a large file never has to be buffered whole.
  const preSliced = upstream.status === 206;
  const length = range ? range.end - range.start + 1 : e.size;
  res.writeHead(range ? 206 : 200, {
    ...headers,
    "Content-Length": String(length),
    ...(range ? { "Content-Range": `bytes ${range.start}-${range.end}/${e.size}` } : {}),
  });

  const reader = upstream.body.getReader();
  let seen = 0; // bytes consumed from the upstream body
  let written = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      let chunk = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
      if (range && !preSliced) {
        const chunkStart = seen;
        seen += chunk.length;
        if (seen <= range.start) continue; // still before the window
        const from = Math.max(0, range.start - chunkStart);
        const to = Math.min(chunk.length, range.end - chunkStart + 1);
        if (to <= from) break;
        chunk = chunk.subarray(from, to);
      } else {
        seen += chunk.length;
      }
      written += chunk.length;
      if (res.destroyed) break;
      if (!res.write(chunk)) {
        // A client that walks away mid-download — Finder cancels a preview on every arrow key —
        // never emits `drain`. Waiting on that alone would park this handler forever and hold the
        // execd response open with it, one leaked connection per abandoned read. Whichever of the
        // two fires first wins.
        await new Promise<void>((resolve) => {
          const done = (): void => {
            res.off("drain", done);
            res.off("close", done);
            resolve();
          };
          res.once("drain", done);
          res.once("close", done);
        });
      }
      if (res.destroyed) break;
      if (written >= length) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  res.end();
}

/** A single-range `Range` header against a known size. Multi-range is ignored (served whole). */
export function parseRange(header: string | string[] | undefined, size: number): { start: number; end: number } | "unsatisfiable" | undefined {
  const raw = Array.isArray(header) ? header[0] : header;
  const m = /^bytes=(\d*)-(\d*)$/.exec((raw ?? "").trim());
  if (!m) return undefined;
  if (size === 0) return "unsatisfiable";
  let start: number;
  let end: number;
  if (m[1] === "") {
    // A suffix range: the LAST n bytes.
    const n = Number(m[2]);
    if (!m[2] || !Number.isFinite(n) || n <= 0) return "unsatisfiable";
    start = Math.max(0, size - n);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= size) return "unsatisfiable";
  return { start, end };
}

async function putFile(req: IncomingMessage, res: ServerResponse, view: View, rel: string): Promise<void> {
  if (!rel) return plain(res, 405, "cannot write the collection root");
  // A partial PUT would need a read-modify-write through execd for every chunk. No client we
  // support uses it, and answering 501 is far better than silently writing the fragment whole.
  if (req.headers["content-range"]) return plain(res, 501, "partial PUT is not supported");

  if (isDropped(rel)) {
    // Accepted and dropped — see DROPPED. The client must believe this succeeded or it retries
    // forever and eventually reports the whole copy as failed.
    req.resume();
    return void res.writeHead(201, { "Content-Length": "0" }).end();
  }

  const before = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (before?.self.isDir) return plain(res, 405, "is a collection");

  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > MAX_PUT_BYTES) {
    return plain(res, 413, `file exceeds ${Math.round(MAX_PUT_BYTES / 1024 / 1024)}MB`);
  }

  // 0644: ordinary workspace files, not the 0600 the secrets vault uses.
  try {
    await writeFileStream(view.sandboxId, absOf(view, rel), req, {
      mode: 0o644,
      maxBytes: MAX_PUT_BYTES,
      ...(Number.isFinite(declared) ? { contentLength: declared } : {}),
    });
  } catch (e) {
    if (e instanceof UploadTooLarge || (e as Error)?.name === "UploadTooLarge" || String((e as Error)?.cause ?? "").includes("UploadTooLarge")) {
      return plain(res, 413, `file exceeds ${Math.round(MAX_PUT_BYTES / 1024 / 1024)}MB`);
    }
    throw e;
  }

  const after = await statTree(view.sandboxId, absOf(view, rel), 0);
  const headers: Record<string, string> = { "Content-Length": "0" };
  if (after) headers.ETag = etagOf(after.self);
  res.writeHead(before ? 204 : 201, headers);
  res.end();
}

async function deleteEntry(res: ServerResponse, view: View, rel: string): Promise<void> {
  if (!rel) return plain(res, 403, "cannot delete the mount root");
  if (isDropped(rel)) return void res.writeHead(204, { "Content-Length": "0" }).end();
  const before = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (!before) return plain(res, 404, "not found");
  const r = await run(view.sandboxId, `rm -rf -- "$ISO_A"`, { envs: { ISO_A: absOf(view, rel) }, timeoutMs: 60_000 });
  if (!r.ok) return plain(res, 403, r.stderr.trim().slice(0, 200) || "delete failed");
  locksBySandbox.get(view.sandboxId)?.delete(rel);
  res.writeHead(204, { "Content-Length": "0" });
  res.end();
}

async function mkcol(req: IncomingMessage, res: ServerResponse, view: View, rel: string): Promise<void> {
  // A body on MKCOL means an extended MKCOL we do not implement (RFC 5689) — 415 is the specified
  // answer, and it is better than creating a plain collection the client then thinks is configured.
  const body = await readBody(req, 64 * 1024);
  if (body === undefined) return plain(res, 413, "body too large");
  if (body.trim()) return plain(res, 415, "MKCOL body is not supported");
  if (!rel) return plain(res, 405, "already exists");
  const abs = absOf(view, rel);
  const r = await run(
    view.sandboxId,
    `[ -e "$ISO_A" ] && { echo exists >&2; exit 2; }; [ -d "$(dirname -- "$ISO_A")" ] || { echo noparent >&2; exit 3; }; mkdir -- "$ISO_A"`,
    { envs: { ISO_A: abs }, timeoutMs: 30_000 },
  );
  if (!r.ok) {
    const why = r.stderr.trim();
    if (why.includes("exists")) return plain(res, 405, "already exists");
    if (why.includes("noparent")) return plain(res, 409, "parent collection does not exist");
    return plain(res, 403, why.slice(0, 200) || "mkcol failed");
  }
  res.writeHead(201, { "Content-Length": "0" });
  res.end();
}

/**
 * The `Destination` header as a path under this mount, or undefined when it points elsewhere.
 *
 * Clients send an absolute URL, and its host is whatever they mounted — which through the tunnel and
 * the Worker is not a name this process knows. So the HOST is not checked: what is checked is that
 * the path lies under this mount's own prefix, which is the property that actually matters (a
 * destination outside the mount must not be writable).
 */
export function destinationRel(raw: string | string[] | undefined, prefix: string): string | undefined {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return undefined;
  let pathname: string;
  try {
    pathname = value.startsWith("/") ? value.split("?")[0] : new URL(value).pathname;
  } catch {
    return undefined;
  }
  if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) return undefined;
  return davRelPath(pathname.slice(prefix.length));
}

async function moveOrCopy(req: IncomingMessage, res: ServerResponse, view: View, rel: string, prefix: string, isMove: boolean): Promise<void> {
  if (!rel) return plain(res, 403, "cannot move the mount root");
  const to = destinationRel(req.headers.destination, prefix);
  if (to === undefined || to === "") return plain(res, 502, "destination is outside this mount");
  if (to === rel) return plain(res, 403, "source and destination are the same");
  // Moving a collection into itself would recurse; `mv` catches it but with a confusing message.
  if (to.startsWith(`${rel}/`)) return plain(res, 409, "destination is inside the source");
  // …and the other direction is the DESTRUCTIVE one: an overwriting move onto an ANCESTOR of the
  // source (`a/b` → `a`) starts by deleting the destination, which deletes the source with it — the
  // whole subtree gone and the `mv` that followed failing anyway. Refuse it before anything runs.
  if (rel.startsWith(`${to}/`)) return plain(res, 409, "destination contains the source");

  const overwrite = String(req.headers.overwrite ?? "T").trim().toUpperCase() !== "F";
  const source = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (!source) return plain(res, 404, "not found");
  const target = await statTree(view.sandboxId, absOf(view, to), 0);
  if (target && !overwrite) return plain(res, 412, "destination exists");

  const envs = { ISO_A: absOf(view, rel), ISO_B: absOf(view, to) };
  const guard = `[ -d "$(dirname -- "$ISO_B")" ] || { echo noparent >&2; exit 3; }; `;
  const cmd = isMove ? `${guard}rm -rf -- "$ISO_B"; mv -- "$ISO_A" "$ISO_B"` : `${guard}rm -rf -- "$ISO_B"; cp -a -- "$ISO_A" "$ISO_B"`;
  const r = await run(view.sandboxId, cmd, { envs, timeoutMs: 120_000 });
  if (!r.ok) {
    if (r.stderr.includes("noparent")) return plain(res, 409, "destination collection does not exist");
    return plain(res, 403, r.stderr.trim().slice(0, 200) || "operation failed");
  }
  if (isMove) locksBySandbox.get(view.sandboxId)?.delete(rel);
  res.writeHead(target ? 204 : 201, { "Content-Length": "0" });
  res.end();
}

async function lock(req: IncomingMessage, res: ServerResponse, view: View, rel: string, prefix: string): Promise<void> {
  const body = (await readBody(req, 64 * 1024)) ?? "";
  const table = locksBySandbox.get(view.sandboxId) ?? new Map<string, ActiveLock>();
  locksBySandbox.set(view.sandboxId, table);
  const ttl = lockTimeout(Array.isArray(req.headers.timeout) ? req.headers.timeout[0] : req.headers.timeout);

  // An empty body is a REFRESH: the lock to extend is named by the If header.
  if (!body.trim()) {
    const tokens = ifTokens(Array.isArray(req.headers.if) ? req.headers.if[0] : (req.headers.if as string | undefined));
    const existing = table.get(rel);
    if (!existing || !tokens.includes(existing.token) || existing.expires <= Date.now()) {
      return xml(res, 412, `<D:error xmlns:D="DAV:"><D:lock-token-matches-request-uri/></D:error>`);
    }
    existing.expires = Date.now() + ttl;
    return xml(res, 200, `<D:prop xmlns:D="DAV:"><D:lockdiscovery>${activeLockXml(existing)}</D:lockdiscovery></D:prop>`, {
      "Lock-Token": `<${existing.token}>`,
    });
  }

  const existing = table.get(rel);
  if (existing && existing.expires > Date.now() && existing.exclusive) {
    return xml(res, 423, `<D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>`);
  }

  // LOCK on a path that does not exist creates an empty locked resource (RFC 4918 §7.3) — Finder
  // and Explorer both rely on it: they lock the target BEFORE the PUT that fills it.
  const existed = await statTree(view.sandboxId, absOf(view, rel), 0);
  if (!existed && rel && !isDropped(rel)) {
    const r = await run(view.sandboxId, `[ -d "$(dirname -- "$ISO_A")" ] || exit 3; : > "$ISO_A"`, { envs: { ISO_A: absOf(view, rel) }, timeoutMs: 30_000 });
    if (!r.ok) return plain(res, 409, "parent collection does not exist");
  }

  const owner = /<[\w.-]*:?owner(?:\s[^>]*)?>([\s\S]*?)<\/[\w.-]*:?owner\s*>/i.exec(body)?.[1] ?? "";
  const active: ActiveLock = {
    token: `opaquelocktoken:${randomUUID()}`,
    rel,
    depth: String(req.headers.depth ?? "infinity").trim() === "0" ? "0" : "infinity",
    exclusive: !/<[\w.-]*:?shared\s*\/?>/i.test(body),
    owner,
    expires: Date.now() + ttl,
  };
  table.set(rel, active);
  void prefix; // hrefs are not part of a LOCK response body
  xml(res, existed ? 200 : 201, `<D:prop xmlns:D="DAV:"><D:lockdiscovery>${activeLockXml(active)}</D:lockdiscovery></D:prop>`, {
    "Lock-Token": `<${active.token}>`,
  });
}

function unlock(req: IncomingMessage, res: ServerResponse, view: View, rel: string): void {
  const raw = Array.isArray(req.headers["lock-token"]) ? req.headers["lock-token"][0] : req.headers["lock-token"];
  const token = /<([^>]+)>/.exec(raw ?? "")?.[1] ?? raw?.trim();
  const table = locksBySandbox.get(view.sandboxId);
  const existing = table?.get(rel);
  if (!existing || !token || existing.token !== token) {
    return xml(res, 409, `<D:error xmlns:D="DAV:"><D:lock-token-matches-request-uri/></D:error>`);
  }
  table?.delete(rel);
  res.writeHead(204, { "Content-Length": "0" });
  res.end();
}
