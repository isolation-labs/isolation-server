// Git for the code view (PLAN V3, folded into V1): the source-control section of the
// editor's sidebar, the tree decorations and the file menu's git actions all ride
// this API — every operation is an execd git command in the sandbox, no in-sandbox
// server. Scoped to the NESTED repos under /workspace (the workspace root itself is
// the session branch, owned by session sync — it is never listed here).
//
// Command discipline (the listDir lesson): every path rides an env var, never command
// text — the path guards block traversal, not shell metacharacters. Commit messages,
// branch names and path lists ride env vars for the same reason.
import type { IncomingMessage, ServerResponse } from "node:http";
import { run } from "./execd.js";
import { safeRelPath } from "./codeview.js";
import type { View } from "./views.js";

const WORKSPACE = "/workspace";
const MAX_SHOW_BYTES = 10 * 1024 * 1024; // mirrors the editor's file cap
const MAX_PATHS = 500;

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

// A repo directory: workspace-relative, never the root (the session branch), never an
// escape. Returned as the absolute path the git commands use.
export function repoDir(raw: string | null): string | undefined {
  const rel = safeRelPath(raw);
  return rel ? `${WORKSPACE}/${rel}` : undefined;
}

// Repo-relative paths as `git status` printed them; still refuse escapes — an absolute
// path or `..` would let `discard` touch files outside the repo the request names.
// Newlines are refused because the list rides an env var newline-separated.
export function safeRepoPaths(raw: unknown): string[] | undefined {
  const list = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  if (!list.length || list.length > MAX_PATHS) return undefined;
  const out: string[] = [];
  for (const p of list) {
    if (typeof p !== "string" || !p || p.length > 1024) return undefined;
    if (p.startsWith("/") || p.includes("\0") || p.includes("\n") || p.includes("\r")) return undefined;
    if (p.split("/").some((s) => s === "" || s === "..")) return undefined;
    out.push(p);
  }
  return out;
}

// Branch names: what `git check-ref-format --branch` would accept, minus the exotic.
const BRANCH_RE = /^(?!-)(?!.*(\.\.|@\{|\/\/|\/\.|\.\/))[^\s~^:?*[\\\x00-\x1f\x7f]{1,255}(?<!\.lock)(?<![./])$/;
export const safeBranch = (raw: unknown): string | undefined => (typeof raw === "string" && BRANCH_RE.test(raw) ? raw : undefined);

export interface StatusFile {
  path: string;
  index: string; // staged half of the porcelain XY
  work: string; // worktree half
  renamedFrom?: string;
}

export interface RepoStatus {
  dir: string; // workspace-relative
  branch: string; // "" when detached / unborn
  detached: boolean;
  upstream: boolean;
  ahead: number;
  behind: number;
  files: StatusFile[];
  ignored: string[]; // repo-relative; directories carry a trailing slash
  error?: string;
}

// C-style unquoting of a porcelain path ("a\"b", "\303\251"): git quotes paths carrying
// quotes, backslashes or control bytes even with core.quotePath=false.
export function unquotePath(s: string): string {
  if (!(s.startsWith('"') && s.endsWith('"') && s.length >= 2)) return s;
  const bytes: number[] = [];
  const body = s.slice(1, -1);
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== "\\") {
      bytes.push(...Buffer.from(ch, "utf8"));
      continue;
    }
    const n = body[++i];
    if (n === undefined) break;
    const oct = /^[0-7]{3}/.exec(body.slice(i));
    if (oct) {
      bytes.push(parseInt(oct[0], 8));
      i += 2;
      continue;
    }
    const map: Record<string, number> = { n: 10, t: 9, r: 13, b: 8, f: 12, a: 7, v: 11, '"': 34, "\\": 92 };
    bytes.push(map[n] ?? n.charCodeAt(0));
  }
  return Buffer.from(bytes).toString("utf8");
}

// Parse one repo's `git status --porcelain=v1 -b -uall --ignored` (newline form —
// robust to execd's line-oriented stdout stream; -z output would pick up phantom
// newlines at chunk boundaries).
export function parseStatus(dir: string, text: string): RepoStatus {
  const st: RepoStatus = { dir, branch: "", detached: false, upstream: false, ahead: 0, behind: 0, files: [], ignored: [] };
  for (const line of text.split("\n")) {
    if (!line) continue;
    if (line.startsWith("## ")) {
      const head = line.slice(3);
      if (head.startsWith("HEAD (no branch)")) st.detached = true;
      else if (head.startsWith("No commits yet on ")) st.branch = head.slice("No commits yet on ".length).trim();
      else if (head.startsWith("Initial commit on ")) st.branch = head.slice("Initial commit on ".length).trim();
      else {
        const m = /^(.+?)(?:\.\.\.(\S+))?(?: \[(.*)\])?$/.exec(head);
        st.branch = m?.[1] ?? head;
        st.upstream = !!m?.[2];
        const flags = m?.[3] ?? "";
        st.ahead = Number(/ahead (\d+)/.exec(flags)?.[1] ?? 0);
        st.behind = Number(/behind (\d+)/.exec(flags)?.[1] ?? 0);
      }
      continue;
    }
    if (line.length < 4 || line[2] !== " ") continue;
    const index = line[0];
    const work = line[1];
    const rest = line.slice(3);
    if (index === "!" && work === "!") {
      st.ignored.push(unquotePath(rest));
      continue;
    }
    if (index === "R" || index === "C" || work === "R" || work === "C") {
      // `old -> new`, either side possibly quoted.
      const m = /^("(?:[^"\\]|\\.)*"|[^ ]+(?: [^ ]+)*?) -> (.+)$/.exec(rest);
      if (m) {
        st.files.push({ path: unquotePath(m[2]), index, work, renamedFrom: unquotePath(m[1]) });
        continue;
      }
    }
    st.files.push({ path: unquotePath(rest), index, work });
  }
  return st;
}

// One round trip: discover the nested repos (top level + a few levels down — monorepos
// with sub-repos; `-name .git` covers gitfile worktrees too) and status each. Repo
// blocks are delimited by lines a status can never produce ("=== " needs the XY code
// "==" and a space, which git never emits).
export async function statusAll(sandboxId: string): Promise<{ repos: RepoStatus[] }> {
  const cmd =
    `find ${WORKSPACE} -mindepth 2 -maxdepth 4 -name .git \\( -type d -o -type f \\) -not -path '*/node_modules/*' 2>/dev/null | head -50 | sort | ` +
    `while IFS= read -r g; do d="\${g%/.git}"; printf '=== %s\\n' "\${d#${WORKSPACE}/}"; ` +
    // Two passes: -uall lists untracked files one by one (the tree badges them), but
    // makes --ignored enumerate every file under an ignored directory — so the ignored
    // listing comes from a plain pass, which folds node_modules/ into one entry.
    `git -C "$d" -c core.quotePath=false status --porcelain=v1 -b -uall 2>&1 || printf '!!! status failed\\n'; ` +
    `git -C "$d" -c core.quotePath=false status --porcelain=v1 --ignored=traditional -unormal 2>/dev/null | grep '^!!'; done`;
  const r = await run(sandboxId, cmd, { timeoutMs: 60_000 });
  const repos: RepoStatus[] = [];
  let cur: { dir: string; lines: string[] } | undefined;
  const flush = () => {
    if (!cur) return;
    const text = cur.lines.join("\n");
    const st = parseStatus(cur.dir, text);
    if (cur.lines.some((l) => l.startsWith("!!! ") || l.startsWith("fatal:"))) st.error = cur.lines.find((l) => l.startsWith("fatal:"))?.slice(0, 200) ?? "status failed";
    repos.push(st);
  };
  for (const line of r.stdout.split("\n")) {
    if (line.startsWith("=== ")) {
      flush();
      cur = { dir: line.slice(4), lines: [] };
    } else if (cur) cur.lines.push(line);
  }
  flush();
  return { repos };
}

// The content of a file at HEAD or in the index, byte-exact via base64 (execd's stdout
// is line-oriented; raw text would gain or lose a trailing newline). `content: null`
// = no such blob (untracked at HEAD, deleted from the index).
export async function showBlob(sandboxId: string, repoAbs: string, file: string, rev: "head" | "index"): Promise<{ content: string | null; binary?: boolean } | { error: string }> {
  const spec = rev === "head" ? `HEAD:$ISO_F` : `:0:$ISO_F`;
  // A missing blob (untracked at HEAD, deleted from the index) prints nothing; an EMPTY
  // blob prints the "yes" marker alone — the probe separates the two.
  const r = await run(sandboxId, `git -C "$ISO_REPO" cat-file -e "${spec}" 2>/dev/null && { echo yes; git -C "$ISO_REPO" show "${spec}" | base64; }`, {
    envs: { ISO_REPO: repoAbs, ISO_F: file },
    timeoutMs: 60_000,
  });
  const out = r.stdout.replace(/^\s+/, "");
  if (!out.startsWith("yes")) return { content: null };
  const bytes = Buffer.from(out.slice(3).replace(/\s+/g, ""), "base64");
  if (bytes.length > MAX_SHOW_BYTES) return { error: `file exceeds ${MAX_SHOW_BYTES / 1024 / 1024}MB` };
  if (bytes.subarray(0, 8192).includes(0)) return { content: null, binary: true };
  return { content: bytes.toString("utf8") };
}

export async function branches(sandboxId: string, repoAbs: string): Promise<{ current: string; local: string[]; remote: string[] } | { error: string }> {
  const r = await run(sandboxId, `git -C "$ISO_REPO" for-each-ref --format='%(HEAD)%09%(refname)' refs/heads refs/remotes`, { envs: { ISO_REPO: repoAbs }, timeoutMs: 20_000 });
  if (!r.ok) return { error: r.stderr.trim().slice(0, 200) || "not a git repository" };
  let current = "";
  const local: string[] = [];
  const remote = new Set<string>();
  for (const line of r.stdout.split("\n")) {
    const [head, ref] = line.split("\t");
    if (!ref) continue;
    if (ref.startsWith("refs/heads/")) {
      const name = ref.slice("refs/heads/".length);
      local.push(name);
      if (head === "*") current = name;
    } else if (ref.startsWith("refs/remotes/")) {
      // refs/remotes/<remote>/<branch> — offer the branch; `git switch <branch>` tracks it.
      const name = ref.slice("refs/remotes/".length).split("/").slice(1).join("/");
      if (name && name !== "HEAD") remote.add(name);
    }
  }
  return { current, local, remote: [...remote].filter((b) => !local.includes(b)).sort() };
}

// A shell loop over the newline-separated ISO_PATHS env var, running `$cmd` per path
// as "$f". Per-path git invocations keep every path in an env var — `--pathspec-from-
// file` would need stdin execd can't feed — and stop at the first failure.
const perPath = (cmd: string): string => `cd "$ISO_REPO" && printf '%s\\n' "$ISO_PATHS" | while IFS= read -r f; do [ -n "$f" ] || continue; ${cmd} || exit 1; done`;

// eslint-disable-next-line complexity
export async function gitOp(sandboxId: string, repoAbs: string, body: Record<string, unknown>): Promise<{ ok: true; output?: string } | { error: string }> {
  const op = String(body.op ?? "");
  const envs: Record<string, string> = { ISO_REPO: repoAbs, GIT_TERMINAL_PROMPT: "0" };
  let cmd = "";
  let timeoutMs = 60_000;
  if (op === "stage" || op === "unstage" || op === "discard") {
    const paths = safeRepoPaths(body.paths ?? body.path);
    if (!paths) return { error: "bad path" };
    envs.ISO_PATHS = paths.join("\n");
    if (op === "stage") cmd = perPath(`git add -A -- "$f"`);
    else if (op === "unstage") cmd = perPath(`git reset -q HEAD -- "$f"`);
    // Discard = worktree back to the index (VS Code semantics); an untracked file is
    // simply removed. A tracked path that's a directory (folder row) checks out whole.
    else cmd = perPath(`if git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then git checkout -q -- "$f" && git clean -qfd -- "$f"; else rm -rf -- "$f"; fi`);
  } else if (op === "stageAll") cmd = `git -C "$ISO_REPO" add -A`;
  else if (op === "unstageAll") cmd = `git -C "$ISO_REPO" reset -q`;
  else if (op === "discardAll") cmd = `git -C "$ISO_REPO" checkout -q -- . && git -C "$ISO_REPO" clean -qfd`;
  else if (op === "commit") {
    const message = typeof body.message === "string" ? body.message.trim() : "";
    if (!message) return { error: "commit message required" };
    if (Buffer.byteLength(message, "utf8") > 16 * 1024) return { error: "commit message too long" };
    envs.ISO_MSG = message;
    cmd = `git -C "$ISO_REPO" commit${body.amend === true ? " --amend" : ""}${body.all === true ? " -a" : ""} -m "$ISO_MSG"`;
  } else if (op === "push") {
    // No upstream yet → publish the branch on origin (VS Code's "Publish Branch").
    cmd = `cd "$ISO_REPO" && if git rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1; then git push${body.force === true ? " --force-with-lease" : ""}; else git push -u origin HEAD; fi`;
    timeoutMs = 180_000;
  } else if (op === "pull") {
    cmd = `git -C "$ISO_REPO" pull`;
    timeoutMs = 180_000;
  } else if (op === "fetch") {
    cmd = `git -C "$ISO_REPO" fetch --prune`;
    timeoutMs = 180_000;
  } else if (op === "checkout") {
    const branch = safeBranch(body.branch);
    if (!branch) return { error: "bad branch name" };
    envs.ISO_BRANCH = branch;
    cmd = `git -C "$ISO_REPO" switch "$ISO_BRANCH"`;
  } else if (op === "createBranch") {
    const branch = safeBranch(body.branch);
    if (!branch) return { error: "bad branch name" };
    envs.ISO_BRANCH = branch;
    cmd = `git -C "$ISO_REPO" switch -c "$ISO_BRANCH"`;
  } else return { error: "unknown op" };
  const r = await run(sandboxId, cmd, { envs, timeoutMs });
  if (!r.ok) return { error: (r.stderr || r.stdout).trim().slice(0, 400) || `${op} failed` };
  return { ok: true, output: (r.stdout + r.stderr).trim().slice(0, 400) };
}

// Routes under the code view's /api/git/*. `rest` is the path after /api/git.
export async function handleGitApi(req: IncomingMessage, res: ServerResponse, view: View, rest: string, q: URLSearchParams): Promise<void> {
  const method = req.method ?? "GET";
  if (rest === "/status" && method === "GET") return json(res, 200, await statusAll(view.sandboxId));
  const repo = repoDir(q.get("repo"));
  if (rest === "/show" && method === "GET") {
    if (!repo) return json(res, 400, { error: "bad repo path" });
    const paths = safeRepoPaths(q.get("path"));
    const rev = q.get("rev") === "head" ? "head" : "index";
    if (!paths) return json(res, 400, { error: "bad path" });
    const out = await showBlob(view.sandboxId, repo, paths[0], rev);
    return json(res, "error" in out ? 409 : 200, out);
  }
  if (rest === "/branches" && method === "GET") {
    if (!repo) return json(res, 400, { error: "bad repo path" });
    const out = await branches(view.sandboxId, repo);
    return json(res, "error" in out ? 409 : 200, out);
  }
  if (rest === "/op" && method === "POST") {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const c of req) {
      total += (c as Buffer).length;
      if (total > 256 * 1024) return json(res, 413, { error: "body too large" });
      chunks.push(c as Buffer);
    }
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: "bad json" });
    }
    const target = repoDir(typeof body.repo === "string" ? body.repo : null);
    if (!target) return json(res, 400, { error: "bad repo path" });
    const out = await gitOp(view.sandboxId, target, body);
    return json(res, "error" in out ? 409 : 200, out);
  }
  return json(res, 404, { error: "unknown api route" });
}
