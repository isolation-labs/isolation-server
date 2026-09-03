// Launch orchestration — the isolation-server slice of what the old daemon's launch path
// did, re-targeted at OpenSandbox: create the sandbox, materialize the launch
// secrets, clone the repos, start the view processes. The devcontainer pipeline and
// workspace persistence layer on top of this in later phases; nothing here persists
// a secret beyond the sandbox's lifetime.
import { randomBytes } from "node:crypto";
import { createSandbox, type Sandbox } from "./opensandbox.js";
import { run, waitReady, writeFile } from "./execd.js";
import { sealedOrInline } from "./envelope.js";
import { restoreWorkspace, type WorkspaceSink } from "./persistence.js";
import { analyzeLaunch, cleanScratch, fetchDetectionFiles, type AnalysisRepo, type LaunchSpec } from "./analysis.js";
import { cacheKey, dependencyHash, workspaceHash } from "./hashes.js";
import { buildDependencyCacheInBackground, cacheImageAvailable, cacheImageTag, reposWithDeps } from "./cache.js";
import { dockerAvailable, ensureSpecImage, type ImageRegistry } from "./images.js";
import { addView, mintViewToken, newWebSlug, viewsForSandbox, type View, type ViewType } from "./views.js";
import { cloneTarget, installVault, parseVaultManifest, sidecarCreateSpec, vaultCoversHost, type VaultManifest, type VaultSummary } from "./vault.js";

// The launch's persistence envelope (same shape the web sends the daemon today:
// `workspaceId` + `persistence.workspace.{endpoint, creds}`).
// `persistence.cache` — the image registry a Cloud VM pulls/pushes spec + cache images
// through (creds optional: managed VMs are already docker-logged-in by provisioning).
function parseImageRegistry(body: LaunchRequest): ImageRegistry | undefined {
  const c = ((body.persistence ?? {}) as { cache?: Record<string, unknown> }).cache;
  const registry = typeof c?.registry === "string" ? c.registry.trim() : "";
  const repository = typeof c?.repository === "string" ? c.repository.trim() : "";
  if (!registry || !repository) return undefined;
  return { registry, repository, username: typeof c?.username === "string" ? c.username : undefined, password: typeof c?.password === "string" ? c.password : undefined };
}

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

export const TOOLING_IMAGE = "isolation-server/tooling:0.6"; // 0.6: claude + codex CLIs
const TERMINAL_PORT = 7681;
const DIRECTORY_PORT = 8055;
const WEB_SHADOW_BASE = 42000;

// Runtime metadata values are k8s-style labels: alphanumeric/-/_/. , ≤63 chars,
// alphanumeric at both ends. Display names live on the session record instead.
const labelSafe = (s: string): string =>
  s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "").slice(0, 63) || "session";

// --- validation (ported rules: the gate must never write outside /workspace or
// let a launch body shadow system env) -----------------------------------------

const VAR_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RESERVED_PREFIXES = ["ISOLATION_SERVER_", "ISO_", "OPEN_SANDBOX_"];
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

// The session-wide AI credential (the cloud's "launch credential" — claude.ts CredPair). Two
// shapes: an API key (usually a scoped isogw_… gateway token + the metering gateway's base URL;
// a real key + endpoint for providers the gateway can't front) and a subscription OAuth token
// (injected raw — Anthropic blocks proxied OAuth). Arrives sealed to this server's pairing
// secret (`claudeBlob`) or inline for a plain gateway pair (`claude`).
export interface AiCred {
  auth: "apiKey" | "subscription";
  apiKey?: string;
  oauthToken?: string;
  baseUrl?: string;
}

export function parseAiCred(body: unknown): AiCred | undefined {
  const b = (body ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);
  if (b.auth === "apiKey" && str(b.apiKey)) return { auth: "apiKey", apiKey: str(b.apiKey), baseUrl: str(b.baseUrl) };
  if (b.auth === "subscription" && str(b.oauthToken)) return { auth: "subscription", oauthToken: str(b.oauthToken) };
  return undefined;
}

// The env the harnesses and the user's own terminal read. Claude Code takes either shape
// natively; goose and other OpenAI-compatible tooling read the same pair under their own
// names, exported at the adapter layer from these.
export function aiCredEnv(cred: AiCred): Record<string, string> {
  if (cred.auth === "subscription") return { CLAUDE_CODE_OAUTH_TOKEN: cred.oauthToken! };
  return { ANTHROPIC_API_KEY: cred.apiKey!, ...(cred.baseUrl ? { ANTHROPIC_BASE_URL: cred.baseUrl } : {}) };
}

// A credential replaces the WHOLE pair, so every var it could own is cleared first: a
// leftover ANTHROPIC_API_KEY from the environment config would out-rank the chosen
// subscription token, and a leftover ANTHROPIC_BASE_URL would ship the chosen token to
// someone else's endpoint. Partial application is worse than none.
export const AI_ENV_KEYS = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN"];

export function applyAiCred(env: Record<string, string>, cred: AiCred): void {
  for (const k of AI_ENV_KEYS) delete env[k];
  Object.assign(env, aiCredEnv(cred));
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
async function cloneRepo(sandboxId: string, repo: RepoSpec, creds: GitCreds, vault?: VaultManifest): Promise<void> {
  const override = creds.repoTokens.find((t) => t.url === repo.url)?.token;
  const sshKey = creds.repoSshKeys.find((k) => k.url === repo.url)?.key;
  const isSsh = /^(git@|ssh:\/\/)/.test(repo.url);
  const dest = `/workspace/${repo.name}`;
  const branchArg = repo.branch ? ` --branch ${JSON.stringify(repo.branch)}` : "";
  const envs: Record<string, string> = {};
  let cleanup = "";
  // Gateway-delivered git (PLAN §5b): the remote IS the gateway route; the sidecar authenticates it.
  const cloneUrl = cloneTarget(vault, repo.url).url;

  if (isSsh && sshKey) {
    const keyPath = `/tmp/.iso-key-${randomBytes(4).toString("hex")}`;
    await writeFile(sandboxId, keyPath, sshKey.endsWith("\n") ? sshKey : `${sshKey}\n`, 0o600);
    envs.GIT_SSH_COMMAND = `ssh -i ${keyPath} -o StrictHostKeyChecking=accept-new`;
    cleanup = `; rm -f ${keyPath}`;
  } else if (!isSsh && vaultCoversHost(vault, cloneUrl)) {
    // The vault fronts this host (PLAN §5b): the sidecar injects the credential on every
    // request, so git sees an already-authenticated remote — no token, no askpass, and
    // `git push` from a terminal later works the same way.
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

  const r = await run(sandboxId, `git clone${branchArg} ${JSON.stringify(cloneUrl)} ${JSON.stringify(dest)}${cleanup}`, {
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
  agentId?: string; // agent views: the roster definition id
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
  } else if (w.type === "code" || w.type === "agent") {
    // First-party doorman-served views (PLAN V1/V2): no sandbox port, no process.
    port = 0;
  } else if (!port) {
    port = nextFree(w.type === "terminal" ? TERMINAL_PORT : DIRECTORY_PORT);
  }
  // An agent view IS a thread (threads.ts): its key names the transcript in the workspace tree, so
  // a view created in-session without a workspace key mints one — saving the view into the
  // workspace later keeps the same chat.
  const specKey = w.specKey ?? (w.type === "agent" ? `agent-${randomBytes(4).toString("hex")}` : undefined);
  const v = addView(sandboxId, w.type, port, { label: w.label, specKey, appPath, appPort, ...(w.type === "agent" && w.agentId ? { agentId: w.agentId } : {}), ...(w.type === "web" ? { slug: newWebSlug() } : {}) });
  await startViewProcess(sandboxId, v);
  return v;
}

// Start the in-sandbox process a view type needs and return its inside port.
// terminal: ttyd fronting a per-view tmux session — every browser tab attaches the
// same tmux (shared state + live mirror), and a ttyd restart reattaches. web: the
// app's own port, nothing to start. code: nothing at all — the doorman serves the
// Monaco editor itself over execd's file APIs (PLAN V1).
async function startViewProcess(sandboxId: string, view: View): Promise<void> {
  // execd's background mode owns each process's lifetime — no nohup/& wrappers (a
  // shell that exits immediately takes its children with it).
  if (view.type === "terminal") {
    await run(sandboxId, `ttyd --writable -p ${view.port} tmux new -A -s iso-view-${view.id}`, {
      cwd: "/workspace",
      background: true,
    });
  } else if (view.type === "web" && view.appPort) {
    await startWebForwarder(view);
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

// Dual-stack loopback forwarder: 0.0.0.0:<shadow> → 127.0.0.1 or [::1]:<appPort>, whichever
// accepts, per connection (so it also copes with the app restarting). Its argv carries the
// VIEW ID, so lifecycle ops (delete, self-heal) target exactly this view's process — never a
// neighbour that happens to reuse the port. Any stale forwarder on the port is cleared first
// (it would win the bind and point at the wrong app).
export async function startWebForwarder(view: View): Promise<void> {
  if (!view.appPort) return;
  await writeFile(view.sandboxId, PORTFWD_PATH, PORTFWD_SRC, 0o644);
  await run(view.sandboxId, `pkill -f "portfwd.mjs ${view.port} " || true`);
  await run(view.sandboxId, `$(command -v iso-node || command -v node) ${PORTFWD_PATH} ${view.port} ${view.appPort} ${view.id}`, { cwd: "/workspace", background: true });
}

// True when this view's forwarder process is alive inside its sandbox.
export async function webForwarderAlive(view: View): Promise<boolean> {
  const r = await run(view.sandboxId, `pgrep -f "portfwd.mjs ${view.port} ${view.appPort ?? 0} ${view.id}" >/dev/null && echo alive || echo dead`, { timeoutMs: 10_000 });
  return /alive/.test(r.stdout);
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
  claude?: unknown; // sealed string or inline AiCred — the session-wide AI credential
  vault?: unknown; // sealed string or inline VaultManifest (PLAN §5b) — EVERY credential, via the sidecar
  git?: { name?: string; email?: string };
  env?: Record<string, string>;
  metadata?: Record<string, string>;
  // Live progress callback — the session layer mirrors it into the record the web polls.
  onPhase?: (phase: string) => void;
  // Fires as soon as the sandbox exists — BEFORE clones and views — so the session layer can
  // register the agent roster before any agent view's first request lands.
  onSandbox?: (sandboxId: string) => void;
}

export interface LaunchResult {
  sandbox: Sandbox;
  views: (View & { path: string; token: string })[];
  vault?: VaultSummary;
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
  // The AI credential last, and as a whole pair (see applyAiCred), so the deliberately-chosen
  // provider beats plain env vars of the same names (the cloud already applied its own
  // precedence — environment override → agent/account choice — before sealing). Nothing is
  // written to disk; the value lives only in the sandbox's env for the sandbox's lifetime.
  const aiCred = parseAiCred(sealedOrInline(body.claude));
  if (aiCred) applyAiCred(env, aiCred);
  // The Credential Vault manifest (PLAN §5b). Its `env` is NON-secret routing (gateway base
  // URLs, placeholder keys) and rides the container env under the same validation as any
  // launch var; the values themselves go to the sidecar after the sandbox is up.
  const vault = parseVaultManifest(sealedOrInline(body.vault));
  if (vault?.env) {
    const vars = parseEnvConfig({ vars: Object.entries(vault.env).map(([name, value]) => ({ name, value })) }).vars;
    // Same whole-pair discipline as applyAiCred: if the manifest routes the Anthropic pair at
    // all, it owns ALL of it. Otherwise a manifest that sets only ANTHROPIC_BASE_URL would
    // leave the session's CLAUDE_CODE_OAUTH_TOKEN in place and ship that RAW subscription
    // token to the gateway slot — the exact redirection applyAiCred exists to prevent.
    if (vars.some((v) => AI_ENV_KEYS.includes(v.name))) for (const k of AI_ENV_KEYS) delete env[k];
    for (const v of vars) env[v.name] = v.value;
  }

  // The image (PLAN O4): analyze the repos' detection files host-side, hash them, and
  // build/reuse `isolation-server-spec:<wsHash>` — a repo's own .devcontainer (image / Dockerfile /
  // features) or a generated language base, plus our tooling layer. An explicit `image`
  // in the body wins; no docker CLI on the host (or a build failure) → the static
  // tooling image, so a launch never dies on image prep.
  let image = body.image?.trim() || "";
  let spec: LaunchSpec | undefined;
  const analysisRepos: AnalysisRepo[] = repos.map((r) => {
    // A gateway-delivered repo is fetched host-side from the gateway remote with its scoped token.
    const via = cloneTarget(vault, r.url);
    return {
      url: via.url,
      dir: r.name,
      branch: r.branch,
      token: via.token ?? gitCreds.repoTokens.find((t) => t.url === r.url)?.token ?? (/github\.com/.test(r.url) ? gitCreds.githubOauth : undefined),
    };
  });
  // Dependency cache: when a cache image for this exact (workspace, dependencies) pair
  // exists, launch FROM it and restore the baked deps post-clone; otherwise launch from
  // the spec image and build the cache in the background for next time.
  let cacheDirs: string[] = [];
  let startCacheBuild: (() => void) | undefined;
  if (!image && dockerAvailable()) {
    const scratchId = `a-${randomBytes(4).toString("hex")}`;
    let keepScratch = false;
    try {
      body.onPhase?.("analyzing repositories");
      const scratch = fetchDetectionFiles(analysisRepos, scratchId);
      spec = analyzeLaunch(scratch);
      const wsHash = workspaceHash(scratch);
      log(`analysis: ${spec.source} config${spec.repoDir ? ` (${spec.repoDir}/.devcontainer)` : ""} → base ${spec.devContainer.image ?? "(default)"}; wsHash ${wsHash.slice(0, 12)}`);
      body.onPhase?.("preparing image");
      const registry = parseImageRegistry(body);
      const specImage = await ensureSpecImage(spec, analysisRepos, wsHash, (l) => body.onPhase?.(`preparing image · ${l}`), registry);
      const key = cacheKey(wsHash, dependencyHash(scratch));
      const dirs = reposWithDeps(scratch, repos.map((r) => r.name));
      if (dirs.length && (await cacheImageAvailable(key, registry))) {
        image = cacheImageTag(key);
        cacheDirs = dirs;
        log(`dependency cache hit: ${image}`);
      } else {
        image = specImage;
        if (dirs.length) {
          keepScratch = true; // the background build reads the scratch manifests
          startCacheBuild = () => buildDependencyCacheInBackground(key, specImage, scratch, dirs, () => cleanScratch(scratchId), registry);
        }
      }
    } catch (e) {
      log(`image pipeline failed, using the tooling image: ${String((e as Error)?.message ?? e)}`);
      image = "";
    } finally {
      if (!keepScratch) cleanScratch(scratchId);
    }
  }
  if (!image) image = TOOLING_IMAGE;

  const sandbox = await createSandbox({
    image,
    entrypoint: ["sleep", "infinity"],
    env: Object.keys(env).length ? env : undefined,
    // Metadata values must be label-safe for the runtime (alphanum/-/_/. only, ≤63).
    metadata: { managedBy: "isolation-server", ...(body.name ? { name: labelSafe(body.name) } : {}), ...(body.metadata ?? {}) },
    // A manifest attaches the egress sidecar (the vault lives there); no manifest = no sidecar.
    ...(vault ? sidecarCreateSpec() : {}),
  });
  log(`sandbox ${sandbox.id} created (${image}${vault ? ", credential vault" : ""})`);
  body.onSandbox?.(sandbox.id);

  let vaultSummary: VaultSummary | undefined;
  try {
    await waitReady(sandbox.id);

    // Credentials BEFORE anything that needs the network authenticated (clones, hooks).
    if (vault) {
      body.onPhase?.("installing credentials");
      try {
        vaultSummary = await installVault(sandbox.id, vault);
      } catch (e) {
        // A credential the sidecar won't take must not kill the launch: the session comes up
        // without a vault (private clones and AI calls then fail visibly, on their own), and the
        // record says so (revision 0) instead of a dead sandbox saying nothing.
        const msg = String((e as Error)?.message ?? e);
        log(`credential vault install failed — continuing without it: ${msg}`);
        vaultSummary = { revision: 0, credentials: vault.credentials.map((c) => c.name), bindings: [`install failed: ${msg.slice(0, 200)}`] };
      }
    }

    // Git author identity (non-secret) before clones, so hooks/commits attribute right.
    const gname = body.git?.name?.trim();
    const gmail = body.git?.email?.trim();
    if (gname && gmail) {
      await run(sandbox.id, `git config --global user.name ${JSON.stringify(gname)} && git config --global user.email ${JSON.stringify(gmail)}`);
    }

    // A ChatGPT subscription as the session's default: `codex` in a terminal must find itself
    // logged in (placeholder access token — the gateway swaps it) and pointed at the gateway.
    if (env.CODEX_SUBSCRIPTION && env.OPENAI_BASE_URL) {
      const { codexLoginFile, shq } = await import("./harness.js");
      const root = env.OPENAI_BASE_URL.replace(/\/v1\/?$/, "");
      await run(sandbox.id, `${codexLoginFile(env.OPENAI_API_KEY ?? "isolation-vault", env.CODEX_ACCOUNT_ID ?? "")} && printf 'chatgpt_base_url = "%s"\\npreferred_auth_method = "chatgpt"\\nmodel_provider = "iso"\\n\\n[model_providers.iso]\\nname = "iso"\\nbase_url = "%s"\\nwire_api = "responses"\\nsupports_websockets = false\\nrequires_openai_auth = true\\n' ${shq(`${root}/backend-api/`)} ${shq(`${root}/backend-api/codex`)} > ~/.codex/config.toml`).catch((e: Error) => log(`codex login files: ${e.message}`));
    }

    body.onPhase?.("cloning repositories");
    for (const repo of repos) {
      log(`cloning ${repo.url} → /workspace/${repo.name}`);
      await cloneRepo(sandbox.id, repo, gitCreds, vault);
    }
    // Cache hit: copy the baked deps (node_modules, .venv, vendor, …) into each fresh
    // clone where missing — cp -a, since /iso and /workspace may be different mounts.
    for (const dir of cacheDirs) {
      body.onPhase?.("restoring cached dependencies");
      await run(sandbox.id, `[ -d /iso/cache/${dir} ] && for e in /iso/cache/${dir}/* /iso/cache/${dir}/.[!.]*; do [ -e "$e" ] || continue; n=$(basename "$e"); [ -e /workspace/${dir}/$n ] || cp -a "$e" /workspace/${dir}/; done; true`, { timeoutMs: 300_000 });
    }
    // Launch has priority; the cache build starts only once the session is on its way.
    startCacheBuild?.();

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
    // devcontainer lifecycle hooks (repository configs): postCreate runs once per fresh
    // sandbox, postStart every boot — inside the sandbox, in the owning repo's dir.
    const hooks = spec?.source === "repository" ? spec.devContainer.raw : undefined;
    if (hooks && spec?.repoDir) {
      const cwd = `/workspace/${spec.repoDir}`;
      for (const [key, label] of [["postCreateCommand", "postCreate"], ["postStartCommand", "postStart"]] as const) {
        const cmd = hooks[key];
        const text = Array.isArray(cmd) ? cmd.map((c) => JSON.stringify(String(c))).join(" ") : typeof cmd === "string" ? cmd : typeof cmd === "object" && cmd ? Object.values(cmd as Record<string, unknown>).map(String).join(" && ") : "";
        if (!text) continue;
        body.onPhase?.(`running ${label}`);
        const r = await run(sandbox.id, text, { cwd, timeoutMs: 900_000 });
        if (!r.ok) log(`${label} hook failed (continuing): ${(r.stderr || r.stdout).trim().slice(-300)}`);
      }
    }
    body.onPhase?.("starting views");

    const views: LaunchResult["views"] = [];
    for (const w of wanted) {
      const v = await scaffoldView(sandbox.id, w);
      if (v) views.push({ ...v, path: `/v/${v.id}/`, token: mintViewToken(v.id) });
    }

    return { sandbox, views, ...(vaultSummary ? { vault: vaultSummary } : {}) };
  } catch (e) {
    // A failed launch must not leak a half-provisioned sandbox — the caller sees
    // the error; the sandbox is gone.
    const { deleteSandbox } = await import("./opensandbox.js");
    await deleteSandbox(sandbox.id).catch(() => undefined);
    throw e;
  }
}
