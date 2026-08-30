// Launch orchestration — the isogate slice of what the old daemon's launch path
// did, re-targeted at OpenSandbox: create the sandbox, materialize the launch
// secrets, clone the repos, start the view processes. The devcontainer pipeline and
// workspace persistence layer on top of this in later phases; nothing here persists
// a secret beyond the sandbox's lifetime.
import { randomBytes } from "node:crypto";
import { createSandbox, type Sandbox } from "./opensandbox.js";
import { run, waitReady, writeFile } from "./execd.js";
import { sealedOrInline } from "./envelope.js";
import { restoreWorkspace, type WorkspaceSink } from "./persistence.js";
import { addView, mintViewToken, viewsForSandbox, type View, type ViewType } from "./views.js";

// The launch's persistence envelope (same shape the web sends the daemon today:
// `workspaceId` + `persistence.workspace.{endpoint, creds}`).
function parseWorkspaceSink(body: LaunchRequest): WorkspaceSink | undefined {
  const p = (body.persistence ?? {}) as { workspace?: { endpoint?: unknown; creds?: unknown; encKey?: unknown } };
  const endpoint = typeof p.workspace?.endpoint === "string" ? p.workspace.endpoint.trim() : "";
  const workspaceId = typeof body.workspaceId === "string" ? body.workspaceId.trim() : "";
  if (!endpoint || !workspaceId) return undefined;
  return {
    endpoint,
    workspaceId,
    creds: typeof p.workspace?.creds === "string" ? p.workspace.creds : undefined,
    encKey: typeof p.workspace?.encKey === "string" ? p.workspace.encKey : undefined,
  };
}

const log = (...a: unknown[]) => console.log("[launch]", ...a);

export const TOOLING_IMAGE = "isogate/tooling:0.4";
const TERMINAL_PORT = 7681;
const CODE_PORT = 13337;
const DIRECTORY_PORT = 8055;
const WEB_SHADOW_BASE = 42000;

// Runtime metadata values are k8s-style labels: alphanumeric/-/_/. , ≤63 chars,
// alphanumeric at both ends. Display names live on the session record instead.
const labelSafe = (s: string): string =>
  s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "").slice(0, 63) || "session";

// --- validation (ported rules: the gate must never write outside /workspace or
// let a launch body shadow system env) -----------------------------------------

const VAR_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RESERVED_PREFIXES = ["ISOGATE_", "ISO_", "OPEN_SANDBOX_"];
const RESERVED_NAMES = new Set(["PATH", "HOME", "GIT_ASKPASS", "GIT_TOKEN", "GIT_SSH_COMMAND"]);

interface EnvConfig {
  files: { path: string; content: string }[];
  vars: { name: string; value: string }[];
}

export function parseEnvConfig(body: unknown): EnvConfig {
  const b = (body ?? {}) as { files?: unknown; vars?: unknown };
  const files: EnvConfig["files"] = [];
  for (const f of Array.isArray(b.files) ? b.files : []) {
    if (typeof f?.path !== "string" || typeof f?.content !== "string") continue;
    const path = f.path.trim().replace(/^\/+/, "");
    if (!path || path.length > 512 || path.split("/").some((s: string) => s === "" || s === "..")) continue;
    files.push({ path, content: f.content });
  }
  const vars: EnvConfig["vars"] = [];
  const seen = new Set<string>();
  for (const v of Array.isArray(b.vars) ? b.vars : []) {
    if (typeof v?.name !== "string" || typeof v?.value !== "string") continue;
    if (!VAR_NAME_RE.test(v.name) || v.name.length > 128 || seen.has(v.name)) continue;
    if (RESERVED_NAMES.has(v.name) || RESERVED_PREFIXES.some((p) => v.name.startsWith(p))) continue;
    if (Buffer.byteLength(v.value, "utf8") > 32 * 1024 || vars.length >= 100) continue;
    seen.add(v.name);
    vars.push({ name: v.name, value: v.value });
  }
  return { files, vars };
}

interface GitCreds {
  githubOauth?: string;
  repoTokens: { url: string; token: string }[];
  repoSshKeys: { url: string; key: string }[];
}

export function parseGitCreds(body: unknown): GitCreds {
  const b = (body ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v : undefined);
  const pairs = (v: unknown, field: "token" | "key") =>
    (Array.isArray(v) ? v : []).flatMap((e: Record<string, unknown>) => {
      const url = str(e?.url);
      const val = str(e?.[field]);
      return url && val ? [{ url, [field]: val } as never] : [];
    });
  return {
    githubOauth: str(b.githubOauth),
    repoTokens: pairs(b.repoTokens, "token"),
    repoSshKeys: pairs(b.repoSshKeys, "key"),
  };
}

// --- repos ---------------------------------------------------------------------

interface RepoSpec {
  url: string;
  name: string;
  branch?: string;
}

export function parseRepos(body: unknown): RepoSpec[] {
  const out: RepoSpec[] = [];
  for (const r of Array.isArray(body) ? body : []) {
    const url = typeof r?.url === "string" ? r.url.trim() : "";
    if (!url) continue;
    const fallback = url.replace(/\/+$/, "").split("/").pop()?.replace(/\.git$/, "") ?? "repo";
    const name = (typeof r?.name === "string" && r.name.trim() ? r.name.trim() : fallback).replace(/[^A-Za-z0-9._-]/g, "-");
    out.push({ url, name, branch: typeof r?.branch === "string" && r.branch.trim() ? r.branch.trim() : undefined });
  }
  return out;
}

// Clone one repo inside the sandbox. Credentials never touch argv or a URL: HTTPS
// tokens flow through a generic GIT_ASKPASS script reading $GIT_TOKEN from the
// command's env; SSH keys are written 0600, referenced via GIT_SSH_COMMAND, and
// deleted right after. Public repos clone tokenless.
async function cloneRepo(sandboxId: string, repo: RepoSpec, creds: GitCreds): Promise<void> {
  const override = creds.repoTokens.find((t) => t.url === repo.url)?.token;
  const sshKey = creds.repoSshKeys.find((k) => k.url === repo.url)?.key;
  const isSsh = /^(git@|ssh:\/\/)/.test(repo.url);
  const dest = `/workspace/${repo.name}`;
  const branchArg = repo.branch ? ` --branch ${JSON.stringify(repo.branch)}` : "";
  const envs: Record<string, string> = {};
  let cleanup = "";

  if (isSsh && sshKey) {
    const keyPath = `/tmp/.iso-key-${randomBytes(4).toString("hex")}`;
    await writeFile(sandboxId, keyPath, sshKey.endsWith("\n") ? sshKey : `${sshKey}\n`, 0o600);
    envs.GIT_SSH_COMMAND = `ssh -i ${keyPath} -o StrictHostKeyChecking=accept-new`;
    cleanup = `; rm -f ${keyPath}`;
  } else if (!isSsh) {
    const token = override ?? creds.githubOauth;
    if (token) {
      const askpass = `/tmp/.iso-askpass-${randomBytes(4).toString("hex")}`;
      await writeFile(sandboxId, askpass, `#!/bin/sh\ncase "$1" in\n  Username*) echo x-access-token ;;\n  *) echo "$GIT_TOKEN" ;;\nesac\n`, 0o700);
      envs.GIT_ASKPASS = askpass;
      envs.GIT_TOKEN = token;
      cleanup = `; rm -f ${askpass}`;
    }
  }

  const r = await run(sandboxId, `git clone${branchArg} ${JSON.stringify(repo.url)} ${JSON.stringify(dest)}${cleanup}`, {
    envs,
    timeoutMs: 300_000,
  });
  if (!r.ok || /^fatal:/m.test(r.stderr)) {
    throw new Error(`clone of ${repo.url} failed: ${(r.stderr || r.stdout).trim().split("\n").slice(-3).join(" / ").slice(0, 400)}`);
  }
}

// --- views ---------------------------------------------------------------------

// The in-sandbox forwarder behind every web view (see startViewProcess). Needs
// node in the image (the tooling image ships it; devcontainer images will get a
// static binary instead — PLAN O4).
const PORTFWD_PATH = "/tmp/.iso-portfwd.mjs";
const PORTFWD_SRC = `import net from "node:net";
const [listen, target] = process.argv.slice(2).map(Number);
const dial = (hosts, onOk, onFail) => {
  if (!hosts.length) return onFail();
  const s = net.connect({ host: hosts[0], port: target });
  s.once("connect", () => onOk(s));
  s.once("error", () => dial(hosts.slice(1), onOk, onFail));
};
net.createServer((c) => {
  c.pause();
  dial(["127.0.0.1", "::1"], (u) => { c.pipe(u).pipe(c); c.resume(); u.on("error", () => c.destroy()); c.on("error", () => u.destroy()); }, () => c.destroy());
}).listen(listen, "0.0.0.0");
`;

export interface ViewSpec {
  type: ViewType;
  port?: number; // web: the in-container app port (or derived from `url`)
  url?: string; // web: the app URL — port + optional subpage (daemon-compatible)
  label?: string;
  specKey?: string;
}

// Create one view (registry entry + in-sandbox process). Shared by launch scaffolding
// and the live create-view endpoint. Returns undefined for an unsatisfiable spec.
export async function scaffoldView(sandboxId: string, w: ViewSpec): Promise<View | undefined> {
  let port = w.port;
  let appPath: string | undefined;
  if (w.type === "web" && w.url) {
    try {
      const u = new URL(w.url);
      port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
      appPath = u.pathname !== "/" || u.search ? `${u.pathname}${u.search}` : undefined;
    } catch {
      /* fall through to bare port */
    }
  }
  // Per-view port allocation: the type's base port, bumped past any port already
  // taken by this sandbox's views — a second terminal must not collide with the
  // first (both processes would race the bind and the doorman would front the
  // survivor for both views).
  const taken = new Set(viewsForSandbox(sandboxId).map((x) => x.port));
  const nextFree = (base: number): number => {
    let p = base;
    while (taken.has(p)) p++;
    return p;
  };
  let appPort: number | undefined;
  if (w.type === "web") {
    if (!port) return undefined; // web needs the app's own port
    // The doorman never targets the app port directly: dev servers routinely bind
    // `localhost` as IPv6-only (Vite → [::1]) while execd's proxy connects over IPv4.
    // A per-view forwarder on an all-interfaces shadow port tries both loopbacks.
    appPort = port;
    port = nextFree(WEB_SHADOW_BASE);
  } else if (!port) {
    const base = w.type === "terminal" ? TERMINAL_PORT : w.type === "code" ? CODE_PORT : DIRECTORY_PORT;
    port = nextFree(base);
  }
  const v = addView(sandboxId, w.type, port, { label: w.label, specKey: w.specKey, appPath, appPort });
  await startViewProcess(sandboxId, v);
  return v;
}

// Start the in-sandbox process a view type needs and return its inside port.
// terminal: ttyd fronting a per-view tmux session — every browser tab attaches the
// same tmux (shared state + live mirror), and a ttyd restart reattaches. web: the
// app's own port, nothing to start. code/directory: land with the tooling image
// growing code-server/a file server (later phase).
async function startViewProcess(sandboxId: string, view: View): Promise<void> {
  // execd's background mode owns each process's lifetime — no nohup/& wrappers (a
  // shell that exits immediately takes its children with it).
  if (view.type === "terminal") {
    await run(sandboxId, `ttyd --writable -p ${view.port} tmux new -A -s iso-view-${view.id}`, {
      cwd: "/workspace",
      background: true,
    });
  } else if (view.type === "code") {
    // Auth is the doorman's job (view tokens); code-server itself runs open on a
    // loopback-only published port. Multi-client natively.
    await run(sandboxId, `code-server --auth none --disable-telemetry --bind-addr 0.0.0.0:${view.port} /workspace`, {
      cwd: "/workspace",
      background: true,
    });
  } else if (view.type === "web" && view.appPort) {
    // Dual-stack loopback forwarder: 0.0.0.0:<shadow> → 127.0.0.1 or [::1]:<appPort>,
    // whichever accepts, per connection (so it also copes with the app restarting).
    await writeFile(sandboxId, PORTFWD_PATH, PORTFWD_SRC, 0o644);
    // Belt and braces: a stale forwarder on this shadow port (e.g. after a gate
    // restart lost the registry) would win the bind and point at the wrong app.
    await run(sandboxId, `pkill -f "portfwd.mjs ${view.port} " || true`);
    await run(sandboxId, `node ${PORTFWD_PATH} ${view.port} ${view.appPort}`, { cwd: "/workspace", background: true });
  } else if (view.type === "directory") {
    // filebrowser emits absolute asset paths, so it must own its public base URL —
    // the doorman forwards the UNSTRIPPED path for directory views to match.
    await run(
      sandboxId,
      `filebrowser --noauth -r /workspace -a 0.0.0.0 -p ${view.port} -b /v/${view.id} -d /tmp/.iso-fb-${view.id}.db`,
      { cwd: "/workspace", background: true },
    );
  }
}

// --- the launch ----------------------------------------------------------------

export interface LaunchRequest {
  name?: string;
  image?: string;
  workspaceId?: string;
  persistence?: unknown; // { workspace: { endpoint, creds } } — R2-agnostic blob sink
  repos?: unknown;
  views?: ViewSpec[];
  envConfig?: unknown; // sealed string or inline {files, vars}
  repoTokens?: unknown; // sealed string or inline GitCreds
  git?: { name?: string; email?: string };
  env?: Record<string, string>;
  metadata?: Record<string, string>;
  // Live progress callback — the session layer mirrors it into the record the web polls.
  onPhase?: (phase: string) => void;
}

export interface LaunchResult {
  sandbox: Sandbox;
  views: (View & { path: string; token: string })[];
}

export async function launch(body: LaunchRequest): Promise<LaunchResult> {
  const repos = parseRepos(body.repos);
  const envConfig = parseEnvConfig(sealedOrInline(body.envConfig));
  const gitCreds = parseGitCreds(sealedOrInline(body.repoTokens));
  const wanted = Array.isArray(body.views) ? body.views : [];

  // Plain vars ride the container env from the start; caller-supplied `env` is
  // reserved for trusted internals, so launch-body vars are validated above.
  const env: Record<string, string> = { ...(body.env ?? {}) };
  for (const v of envConfig.vars) env[v.name] = v.value;

  const sandbox = await createSandbox({
    image: body.image?.trim() || TOOLING_IMAGE,
    entrypoint: ["sleep", "infinity"],
    env: Object.keys(env).length ? env : undefined,
    // Metadata values must be label-safe for the runtime (alphanum/-/_/. only, ≤63).
    metadata: { managedBy: "isogate", ...(body.name ? { name: labelSafe(body.name) } : {}), ...(body.metadata ?? {}) },
  });
  log(`sandbox ${sandbox.id} created (${body.image?.trim() || TOOLING_IMAGE})`);

  try {
    await waitReady(sandbox.id);

    // Git author identity (non-secret) before clones, so hooks/commits attribute right.
    const gname = body.git?.name?.trim();
    const gmail = body.git?.email?.trim();
    if (gname && gmail) {
      await run(sandbox.id, `git config --global user.name ${JSON.stringify(gname)} && git config --global user.email ${JSON.stringify(gmail)}`);
    }

    body.onPhase?.("cloning repositories");
    for (const repo of repos) {
      log(`cloning ${repo.url} → /workspace/${repo.name}`);
      await cloneRepo(sandbox.id, repo, gitCreds);
    }

    // Workspace persistence: restore the shared tree (branch-per-session) when the
    // launch carries a sink. Repos keep their own git and are excluded (v1).
    const sink = parseWorkspaceSink(body);
    if (sink) {
      body.onPhase?.("restoring workspace");
      await restoreWorkspace(sandbox.id, sink, repos.map((r) => r.name));
    }

    // Secret files land AFTER the restore so the launch environment wins; written
    // 0600 before any view/user process runs.
    for (const f of envConfig.files) {
      await writeFile(sandbox.id, `/workspace/${f.path}`, f.content, 0o600);
    }
    body.onPhase?.("starting views");

    const views: LaunchResult["views"] = [];
    for (const w of wanted) {
      const v = await scaffoldView(sandbox.id, w);
      if (v) views.push({ ...v, path: `/v/${v.id}/`, token: mintViewToken(v.id) });
    }

    return { sandbox, views };
  } catch (e) {
    // A failed launch must not leak a half-provisioned sandbox — the caller sees
    // the error; the sandbox is gone.
    const { deleteSandbox } = await import("./opensandbox.js");
    await deleteSandbox(sandbox.id).catch(() => undefined);
    throw e;
  }
}
