// The first-party code view (PLAN V1, with V3's git folded in) — a Monaco editor the
// doorman serves itself.
// No in-sandbox process: the page + assets are bundled into dist/editor at build
// time, and the file operations ride execd's file/exec APIs. Auth happened in the
// doorman before we're called (view token / cookie), so every route here is scoped
// to one sandbox and rooted at /workspace.
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";
import { downloadFile, run, writeFile } from "./execd.js";
import { handleGitApi } from "./codegit.js";
import type { View } from "./views.js";

const EDITOR_DIR = join(dirname(fileURLToPath(import.meta.url)), "editor");
const WORKSPACE = "/workspace";
const MAX_FILE_BYTES = 10 * 1024 * 1024; // read/write cap — the editor is for code, not blobs

const ASSET_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".ttf": "font/ttf",
  ".svg": "image/svg+xml",
};

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

// A workspace-relative path from the query string, or undefined when it escapes.
// The editor only ever sees /workspace; `..`, absolute paths and control bytes are
// refused rather than normalized.
export function safeRelPath(raw: string | null): string | undefined {
  if (raw === null) return undefined;
  const p = raw.replace(/\/+$/, "");
  if (!p || p.length > 1024 || p.startsWith("/") || p.includes("\\")) return undefined;
  if ([...p].some((ch) => ch.charCodeAt(0) < 0x20)) return undefined;
  if (p.split("/").some((s) => s === "" || s === "." || s === "..")) return undefined;
  return p;
}

async function listDir(sandboxId: string, rel: string, res: ServerResponse): Promise<void> {
  const dir = rel ? `${WORKSPACE}/${rel}` : WORKSPACE;
  // `ls -1Ap` marks directories with a trailing slash and is the portable common
  // denominator (GNU and busybox alike) — no -printf, no stat flavor games. The dir
  // rides in an env var, never interpolated into the command text: safeRelPath blocks
  // traversal but NOT shell metacharacters ($, backticks), and `"$D"` inside a shell
  // string is not re-parsed for command substitution — so a name like `x$(id)` lists,
  // it doesn't execute.
  const r = await run(sandboxId, `ls -1Ap "$ISO_LS_DIR"`, { envs: { ISO_LS_DIR: dir }, timeoutMs: 20_000 });
  if (!r.ok) return json(res, 404, { error: r.stderr.trim().slice(0, 200) || "not a directory" });
  const entries = r.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => (line.endsWith("/") ? { name: line.slice(0, -1), dir: true } : { name: line, dir: false }))
    .sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
  json(res, 200, { entries });
}

// The file's mtime (unix seconds) inside the sandbox, or undefined. `stat -c %Y` is
// GNU + busybox common ground. Powers the editor's stale-save detection.
async function mtimeOf(sandboxId: string, rel: string): Promise<number | undefined> {
  const r = await run(sandboxId, `stat -c %Y "$ISO_P" 2>/dev/null`, { envs: { ISO_P: `${WORKSPACE}/${rel}` }, timeoutMs: 10_000 });
  const n = Number(r.stdout.trim());
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

// Tree file operations, one endpoint: create/mkdir/rename/copy/delete. Both paths ride
// env vars (the listDir lesson — safeRelPath blocks traversal, not shell metacharacters)
// and destination-taking ops refuse to clobber an existing target.
async function fileOp(sandboxId: string, body: Record<string, unknown>, res: ServerResponse): Promise<void> {
  const op = String(body.op ?? "");
  const rel = safeRelPath(typeof body.path === "string" ? body.path : null);
  const to = safeRelPath(typeof body.to === "string" ? body.to : null);
  if (!rel) return json(res, 400, { error: "bad path" });
  const envs = { ISO_A: `${WORKSPACE}/${rel}`, ...(to ? { ISO_B: `${WORKSPACE}/${to}` } : {}) };
  const CMDS: Record<string, { cmd: string; needsTo?: boolean }> = {
    create: { cmd: `[ -e "$ISO_A" ] && { echo exists >&2; exit 1; }; : > "$ISO_A"` },
    mkdir: { cmd: `[ -e "$ISO_A" ] && { echo exists >&2; exit 1; }; mkdir -p "$ISO_A"` },
    rename: { cmd: `[ -e "$ISO_B" ] && { echo "target exists" >&2; exit 1; }; mv "$ISO_A" "$ISO_B"`, needsTo: true },
    copy: { cmd: `[ -e "$ISO_B" ] && { echo "target exists" >&2; exit 1; }; cp -a "$ISO_A" "$ISO_B"`, needsTo: true },
    delete: { cmd: `rm -rf "$ISO_A"` },
  };
  const spec = CMDS[op];
  if (!spec) return json(res, 400, { error: "unknown op" });
  if (spec.needsTo && !to) return json(res, 400, { error: "bad target path" });
  const r = await run(sandboxId, spec.cmd, { envs, timeoutMs: 30_000 });
  if (!r.ok) return json(res, 409, { error: r.stderr.trim().slice(0, 200) || `${op} failed` });
  json(res, 200, { ok: true });
}

// Media the editor previews in-page gets a real content type; everything else stays
// octet-stream (text is decoded client-side either way).
const MEDIA_TYPES: Record<string, string> = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".svg": "image/svg+xml", ".webp": "image/webp", ".ico": "image/x-icon", ".bmp": "image/bmp",
  ".avif": "image/avif", ".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
  ".m4v": "video/x-m4v", ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
  ".m4a": "audio/mp4", ".flac": "audio/flac",
};

async function readFile(sandboxId: string, rel: string, res: ServerResponse): Promise<void> {
  const mtime = await mtimeOf(sandboxId, rel);
  const r = await downloadFile(sandboxId, `${WORKSPACE}/${rel}`);
  if (!r.ok || !r.body) {
    return json(res, r.status === 404 ? 404 : 502, { error: `read failed (HTTP ${r.status})` });
  }
  // Stream with a cap: a runaway artifact must not buffer whole into the server.
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = r.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_FILE_BYTES) {
      await reader.cancel().catch(() => undefined);
      return json(res, 413, { error: `file exceeds ${MAX_FILE_BYTES / 1024 / 1024}MB` });
    }
    chunks.push(value);
  }
  res.writeHead(200, {
    "Content-Type": MEDIA_TYPES[rel.slice(rel.lastIndexOf(".")).toLowerCase()] ?? "application/octet-stream",
    "Content-Length": total,
    "Cache-Control": "no-store",
    // Workspace bytes served on the doorman/data-plane origin. The preview loads them
    // as <img>/<video>/<audio> subresources (CSP ignored there), but a direct top-level
    // navigation to this endpoint would render an SVG as a document — its inline script
    // would run with the view cookie and reach api/file, api/save, api/op. Sandbox the
    // response and forbid scripts so that path can never execute, and never sniff.
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "X-Content-Type-Options": "nosniff",
    ...(mtime ? { "X-Iso-Mtime": String(mtime) } : {}),
  });
  for (const c of chunks) res.write(c);
  res.end();
}

async function saveFile(sandboxId: string, rel: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Stale-save gate: when the editor sends the mtime it read, refuse the write if the
  // file moved on underneath it (an agent, a terminal) — the client offers overwrite
  // (retry without the header) or reload. Best-effort: no stat, no gate.
  const expect = Number(req.headers["x-iso-expect-mtime"]);
  if (Number.isFinite(expect) && expect > 0) {
    const cur = await mtimeOf(sandboxId, rel);
    if (cur && cur !== expect) return json(res, 409, { error: "file changed in the sandbox since it was opened", stale: true, mtime: cur });
  }
  const parts: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    total += (c as Buffer).length;
    if (total > MAX_FILE_BYTES) return json(res, 413, { error: `file exceeds ${MAX_FILE_BYTES / 1024 / 1024}MB` });
    parts.push(c as Buffer);
  }
  // 0644, not the secrets' 0600 — these are ordinary workspace files.
  await writeFile(sandboxId, `${WORKSPACE}/${rel}`, Buffer.concat(parts), 0o644);
  json(res, 200, { ok: true, mtime: await mtimeOf(sandboxId, rel) });
}

// Handle a code view's request. `rest` is the path AFTER /v/<id> (always /-prefixed).
// Auth + the token→cookie promotion already happened in the doorman.
export async function handleCodeView(req: IncomingMessage, res: ServerResponse, view: View, rest: string): Promise<void> {
  const method = req.method ?? "GET";
  const q = new URL(req.url ?? "/", "http://x").searchParams;

  if (rest.startsWith("/api/")) {
    try {
      // Source control: the sidebar's git section, tree decorations, diffs and git ops.
      if (rest.startsWith("/api/git/")) return await handleGitApi(req, res, view, rest.slice("/api/git".length), q);
      const raw = q.get("path");
      const rel = raw ? safeRelPath(raw) : undefined;
      if (rest === "/api/list" && method === "GET") {
        // Empty/absent path = the workspace root.
        if (raw && rel === undefined) return json(res, 400, { error: "bad path" });
        return await listDir(view.sandboxId, rel ?? "", res);
      }
      if (rest === "/api/file" && (method === "GET" || method === "PUT")) {
        if (!rel) return json(res, 400, { error: "bad path" });
        return method === "GET" ? await readFile(view.sandboxId, rel, res) : await saveFile(view.sandboxId, rel, req, res);
      }
      if (rest === "/api/op" && method === "POST") {
        const chunks: Buffer[] = [];
        for await (const c of req) {
          chunks.push(c as Buffer);
          if (chunks.reduce((n, b) => n + b.length, 0) > 64 * 1024) return json(res, 413, { error: "body too large" });
        }
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        } catch {
          return json(res, 400, { error: "bad json" });
        }
        return await fileOp(view.sandboxId, body, res);
      }
      return json(res, 404, { error: "unknown api route" });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  // Static: the editor page + its build artifacts. Flat directory, extension-typed,
  // no traversal (a single path segment only).
  const name = rest === "/" || rest === "" ? "index.html" : rest.slice(1);
  const ext = name.slice(name.lastIndexOf("."));
  const type = ASSET_TYPES[ext];
  if (method !== "GET" || !type || name.includes("/") || name.includes("..")) {
    return json(res, 404, { error: "not found" });
  }
  try {
    const file = join(EDITOR_DIR, name);
    const size = statSync(file).size;
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": size,
      // The page must revalidate (it carries the app shell); hashed-ish assets may rest briefly.
      "Cache-Control": name === "index.html" ? "no-cache" : "public, max-age=3600",
    });
    res.end(readFileSync(file));
  } catch {
    json(res, 404, { error: "not found" });
  }
}
