// The git view (PLAN V3) — a doorman-served working-diff panel over ONE repo in the
// sandbox, the same first-party pattern as the code and agent views: the page ships in
// dist/git, and every operation is an execd git command — no in-sandbox server. The
// view may pin a repo directory (`dir`); otherwise the page's own picker chooses among
// the repos it finds (multi-repo workspaces, sub-repos). File names deep-link into the
// V1 code editor via the SPA (`isolation:open-file` postMessage).
//
// Command discipline (the listDir lesson): every path rides an env var, never command
// text — safeRelPath blocks traversal, not shell metacharacters. Commit messages ride
// an env var for the same reason.
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";
import { run } from "./execd.js";
import { safeRelPath } from "./codeview.js";
import type { View } from "./views.js";

const GIT_DIR = join(dirname(fileURLToPath(import.meta.url)), "git");
const WORKSPACE = "/workspace";

const ASSET_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

// The repo dir for a request: the view's pinned dir wins; else the page's ?repo=; "" = /workspace.
function repoDirOf(view: View, q: URLSearchParams): string | undefined {
  const raw = view.dir ?? q.get("repo") ?? "";
  if (raw === "") return "";
  return safeRelPath(raw);
}

const absRepo = (rel: string): string => (rel ? `${WORKSPACE}/${rel}` : WORKSPACE);

// List the git repos under /workspace (top-level + one nested level — monorepos with
// sub-repos). `find -name .git` covers gitfile worktrees too (-d or -f).
async function listRepos(sandboxId: string): Promise<string[]> {
  const r = await run(sandboxId, `find ${WORKSPACE} -maxdepth 3 -name .git \\( -type d -o -type f \\) 2>/dev/null | head -50`, { timeoutMs: 20_000 });
  return r.stdout
    .split("\n")
    .filter(Boolean)
    .map((p) => p.replace(/\/\.git$/, "").replace(`${WORKSPACE}/`, "").replace(WORKSPACE, ""))
    .sort((a, b) => a.localeCompare(b));
}

export interface StatusFile {
  path: string;
  index: string; // staged half of the porcelain XY
  work: string; // worktree half
  renamedFrom?: string;
}

// `git status --porcelain -b -uall -z`: NUL-separated, stable, rename-aware.
async function gitStatus(sandboxId: string, repoRel: string): Promise<{ branch: string; ahead: number; behind: number; files: StatusFile[] } | { error: string }> {
  const r = await run(sandboxId, `git -C "$ISO_REPO" status --porcelain -b -uall -z`, { envs: { ISO_REPO: absRepo(repoRel) }, timeoutMs: 30_000 });
  if (!r.ok) return { error: r.stderr.trim().slice(0, 200) || "not a git repository" };
  // execd streams line-JSON; NUL bytes survive inside the text events.
  const parts = r.stdout.replace(/\n$/, "").split("\0").filter(Boolean);
  let branch = "";
  let ahead = 0;
  let behind = 0;
  const files: StatusFile[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith("## ")) {
      const m = /^## ([^ .]+(?:\.\.\.\S+)?)(?: \[(?:ahead (\d+))?(?:, )?(?:behind (\d+))?\])?/.exec(p);
      branch = (m?.[1] ?? "").split("...")[0];
      ahead = Number(m?.[2] ?? 0);
      behind = Number(m?.[3] ?? 0);
      continue;
    }
    const index = p[0] ?? " ";
    const work = p[1] ?? " ";
    const path = p.slice(3);
    // Renames carry the ORIGIN as the next NUL field.
    if (index === "R" || index === "C") {
      files.push({ path, index, work, renamedFrom: parts[++i] });
    } else {
      files.push({ path, index, work });
    }
  }
  return { branch, ahead, behind, files };
}

async function gitDiff(sandboxId: string, repoRel: string, file: string, staged: boolean): Promise<{ diff: string } | { error: string }> {
  const envs = { ISO_REPO: absRepo(repoRel), ISO_F: file };
  // Untracked files have no diff — synthesize one against /dev/null so the panel still
  // shows the content as additions. `--no-index` exits 1 on differences: `|| true`.
  const st = await run(sandboxId, `git -C "$ISO_REPO" status --porcelain -z -- "$ISO_F" | head -c 4`, { envs, timeoutMs: 20_000 });
  const untracked = st.stdout.startsWith("??");
  const cmd = untracked
    ? `cd "$ISO_REPO" && git diff --no-index --no-color -- /dev/null "$ISO_F" || true`
    : `git -C "$ISO_REPO" diff --no-color ${staged ? "--cached " : ""}-- "$ISO_F"`;
  const r = await run(sandboxId, cmd, { envs, timeoutMs: 30_000 });
  if (!r.ok && !untracked) return { error: r.stderr.trim().slice(0, 200) || "diff failed" };
  // 512KB cap: the panel is for review, not for pathological diffs.
  const text = r.stdout.length > 512 * 1024 ? `${r.stdout.slice(0, 512 * 1024)}\n… (diff truncated)` : r.stdout;
  return { diff: text };
}

async function gitOp(sandboxId: string, repoRel: string, op: string, body: Record<string, unknown>): Promise<{ ok: true } | { error: string }> {
  const file = typeof body.path === "string" ? body.path : "";
  const envs: Record<string, string> = { ISO_REPO: absRepo(repoRel) };
  let cmd = "";
  if (op === "stage" || op === "unstage" || op === "discard") {
    // Repo-relative paths come from `git status` itself; still refuse escapes — an
    // absolute path would let `discard` rm -rf outside the repo the view is scoped to.
    if (!file || file.includes("\0") || file.startsWith("/") || file.split("/").some((s) => s === "..")) return { error: "bad path" };
    envs.ISO_F = file;
    if (op === "stage") cmd = `git -C "$ISO_REPO" add -- "$ISO_F"`;
    else if (op === "unstage") cmd = `git -C "$ISO_REPO" reset -q HEAD -- "$ISO_F"`;
    else {
      // Discard = worktree back to HEAD; an untracked file is simply removed.
      cmd = `cd "$ISO_REPO" && if git ls-files --error-unmatch -- "$ISO_F" >/dev/null 2>&1; then git checkout -- "$ISO_F"; else rm -rf -- "$ISO_F"; fi`;
    }
  } else if (op === "commit") {
    const message = typeof body.message === "string" ? body.message.trim() : "";
    if (!message) return { error: "commit message required" };
    if (Buffer.byteLength(message, "utf8") > 16 * 1024) return { error: "commit message too long" };
    envs.ISO_MSG = message;
    cmd = `git -C "$ISO_REPO" commit -m "$ISO_MSG"`;
  } else {
    return { error: "unknown op" };
  }
  const r = await run(sandboxId, cmd, { envs, timeoutMs: 60_000 });
  if (!r.ok) return { error: (r.stderr || r.stdout).trim().slice(0, 300) || `${op} failed` };
  return { ok: true };
}

export async function handleGitView(req: IncomingMessage, res: ServerResponse, view: View, rest: string): Promise<void> {
  const method = req.method ?? "GET";
  const q = new URL(req.url ?? "/", "http://x").searchParams;

  if (rest.startsWith("/api/")) {
    try {
      if (rest === "/api/repos" && method === "GET") {
        return json(res, 200, { repos: await listRepos(view.sandboxId), pinned: view.dir ?? null });
      }
      const repo = repoDirOf(view, q);
      if (repo === undefined) return json(res, 400, { error: "bad repo path" });
      if (rest === "/api/status" && method === "GET") {
        const out = await gitStatus(view.sandboxId, repo);
        return json(res, "error" in out ? 409 : 200, out);
      }
      if (rest === "/api/diff" && method === "GET") {
        const file = q.get("path") ?? "";
        if (!file || file.startsWith("/") || file.split("/").some((s) => s === "..")) return json(res, 400, { error: "bad path" });
        const out = await gitDiff(view.sandboxId, repo, file, q.get("staged") === "1");
        return json(res, "error" in out ? 409 : 200, out);
      }
      const opm = /^\/api\/(stage|unstage|discard|commit)$/.exec(rest);
      if (opm && method === "POST") {
        const chunks: Buffer[] = [];
        for await (const c of req) {
          chunks.push(c as Buffer);
          if (chunks.reduce((n, b) => n + b.length, 0) > 64 * 1024) return json(res, 413, { error: "body too large" });
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown>;
        } catch {
          return json(res, 400, { error: "bad json" });
        }
        const out = await gitOp(view.sandboxId, repo, opm[1], body);
        return json(res, "error" in out ? 409 : 200, out);
      }
      return json(res, 404, { error: "unknown api route" });
    } catch (e) {
      return json(res, 502, { error: String((e as Error)?.message ?? e) });
    }
  }

  // Static: the git panel app. Flat directory, extension-typed, no traversal.
  const name = rest === "/" || rest === "" ? "index.html" : rest.slice(1);
  const type = ASSET_TYPES[name.slice(name.lastIndexOf("."))];
  if (method !== "GET" || !type || name.includes("/") || name.includes("..")) {
    return json(res, 404, { error: "not found" });
  }
  try {
    const file = join(GIT_DIR, name);
    const size = statSync(file).size;
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": size,
      "Cache-Control": name === "index.html" ? "no-cache" : "public, max-age=3600",
    });
    res.end(readFileSync(file));
  } catch {
    json(res, 404, { error: "not found" });
  }
}
