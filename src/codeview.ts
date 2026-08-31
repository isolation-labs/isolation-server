// The first-party code view (PLAN V1) — a Monaco editor the doorman serves itself.
// No in-sandbox process: the page + assets are bundled into dist/editor at build
// time, and the file operations ride execd's file/exec APIs. Auth happened in the
// doorman before we're called (view token / cookie), so every route here is scoped
// to one sandbox and rooted at /workspace.
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";
import { downloadFile, run, writeFile } from "./execd.js";
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

async function readFile(sandboxId: string, rel: string, res: ServerResponse): Promise<void> {
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
  res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": total, "Cache-Control": "no-store" });
  for (const c of chunks) res.write(c);
  res.end();
}

async function saveFile(sandboxId: string, rel: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const parts: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    total += (c as Buffer).length;
    if (total > MAX_FILE_BYTES) return json(res, 413, { error: `file exceeds ${MAX_FILE_BYTES / 1024 / 1024}MB` });
    parts.push(c as Buffer);
  }
  // 0644, not the secrets' 0600 — these are ordinary workspace files.
  await writeFile(sandboxId, `${WORKSPACE}/${rel}`, Buffer.concat(parts), 0o644);
  json(res, 200, { ok: true });
}

// Handle a code view's request. `rest` is the path AFTER /v/<id> (always /-prefixed).
// Auth + the token→cookie promotion already happened in the doorman.
export async function handleCodeView(req: IncomingMessage, res: ServerResponse, view: View, rest: string): Promise<void> {
  const method = req.method ?? "GET";
  const q = new URL(req.url ?? "/", "http://x").searchParams;

  if (rest.startsWith("/api/")) {
    try {
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
