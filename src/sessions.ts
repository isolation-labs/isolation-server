// The daemon-compatible session surface (PLAN O3). The web's DaemonClient drives
// every server through one wire contract; isolation-server implements the core of it —
// launch/list/get/save/sync/rename/finish, views, changes, logs — so the existing
// web app works against an OpenSandbox server with ZERO cloud-side changes. A
// session here is a thin record over one sandbox: `s-…` id ↔ sandbox id, name,
// state machine (creating → ready | error), and the live launch phase the web
// polls while a launch runs. Records are session-transient state on disk (the
// web's D1 stays the source of truth for what exists).
import { randomBytes } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DATA, PORT, ensureDataDir, getSandbox } from "./config.js";
import { launch, scaffoldView, type LaunchRequest, type ViewSpec } from "./launch.js";
import { deleteSandbox } from "./opensandbox.js";
import { run } from "./execd.js";
import { dropSink, sinkFor } from "./persistence.js";
import { dropViewsForSandbox, viewsForSandbox, type View, type ViewType } from "./views.js";
import { dropSessionAgents, parseAgentSecrets, parseRoster, registerRoster, setAgentCredentials, type AgentDef } from "./agents.js";
import { installVault, parseVaultManifest, vaultPresent, type VaultSummary } from "./vault.js";
import { forgetThreads } from "./threads.js";
import { sealedOrInline } from "./envelope.js";

const log = (...a: unknown[]) => console.log("[sessions]", ...a);
const FILE = join(DATA, "sessions.json");

export type SessionState = "creating" | "ready" | "stopped" | "error";

export interface SessionRecord {
  id: string; // s-xxxxxx — what the web sees
  sandboxId?: string; // set once the sandbox exists
  workspaceId?: string;
  environmentId?: string;
  environmentName?: string;
  name?: string;
  state: SessionState;
  error?: string;
  phase?: string;
  origin?: "local";
  createdAt: number;
  workspaceName?: string; // display name from the launch body (the record is daemon-shaped for clients)
  viewsPending?: number; // countdown for the daemon's viewsProgress contract (0 = all views live)
  roster?: AgentDef[];
  agentSecretsSealed?: string; // the launch's per-agent credentials, still sealed to this server — re-opened on boot
  vault?: VaultSummary; // what the sidecar holds (names only — never values); revision 0 = lost, needs re-mint
}

let sessions: Record<string, SessionRecord> = {};
try {
  sessions = JSON.parse(readFileSync(FILE, "utf8")) as Record<string, SessionRecord>;
} catch {
  sessions = {};
}

// The agent registry is in-memory: after a restart, every session that is still up gets its
// roster (and the agents' sealed credentials) registered again, so a chat never dies with the
// server process while its sandbox lives on.
for (const rec of Object.values(sessions)) {
  if (!rec.sandboxId || rec.state === "error" || !rec.roster?.length) continue;
  registerRoster(rec.workspaceId ?? rec.id, rec.id, rec.sandboxId, rec.roster);
  const secrets = rec.agentSecretsSealed ? parseAgentSecrets(sealedOrInline(rec.agentSecretsSealed)) : [];
  if (secrets.length) setAgentCredentials(rec.id, secrets);
}

function persist(): void {
  ensureDataDir();
  const tmp = `${FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(sessions, null, 2), { mode: 0o600 });
  renameSync(tmp, FILE);
}

export const getSessionRecord = (id: string): SessionRecord | undefined => sessions[id];
export const listSessionRecords = (workspaceId?: string): SessionRecord[] =>
  Object.values(sessions)
    .filter((s) => !workspaceId || s.workspaceId === workspaceId)
    .sort((a, b) => b.createdAt - a.createdAt);
export const sessionForSandbox = (sandboxId: string): SessionRecord | undefined =>
  Object.values(sessions).find((s) => s.sandboxId === sandboxId);

function update(id: string, patch: Partial<SessionRecord>): void {
  const s = sessions[id];
  if (!s) return;
  Object.assign(s, patch);
  persist();
}

// --- the daemon launch body → isolation-server launch ----------------------------------

// What the web actually sends POST /sessions (the subset isolation-server honors; unknown
// fields — agent, agentSecrets, harnesses — are accepted and ignored until the harness
// adapters land (PLAN §5 P1); the session-wide AI credential IS honored now).
export interface DaemonLaunchBody {
  workspace?: {
    name?: string;
    repos?: { url?: string; dir?: string; branch?: string }[];
    defaultViews?: Record<string, { type?: string; label?: string; dir?: string; command?: string; style?: unknown; url?: string; port?: number; agentId?: string }>;
    gitIdentity?: { name?: string; email?: string };
    // PUBLIC ssh keys that may log INTO this session (the member's `ssh` credentials). Non-secret,
    // and the only credential kind delivered into the sandbox as itself — every other one is
    // fronted by the gateway, which is the point of the gateway.
    authorizedKeys?: string[];
  };
  workspaceId?: string;
  environmentId?: string;
  environmentName?: string;
  persistence?: unknown;
  envConfig?: unknown;
  repoTokens?: unknown;
  claudeBlob?: unknown; // the session-wide AI credential, sealed to this server (the usual path)
  claude?: unknown; // inline pair — only ever a scoped gateway token (a raw key is never sent plain)
  vault?: unknown; // the Credential Vault manifest, sealed to this server (PLAN §5b)
  git?: { name?: string; email?: string };
  name?: string;
  origin?: string;
  agents?: unknown; // the workspace's agent roster (PLAN O5); parsed via parseRoster
  agentSecrets?: unknown; // per-agent credentials, sealed to this server ({credentials:[{key, credential}]})
}

const VIEW_TYPES = new Set(["terminal", "code", "directory", "web", "agent"]);

function viewSpecsFrom(body: DaemonLaunchBody): ViewSpec[] {
  const specs: ViewSpec[] = [];
  for (const [key, v] of Object.entries(body.workspace?.defaultViews ?? {})) {
    if (!v?.type || !VIEW_TYPES.has(v.type)) continue;
    // An agent view without a roster binding is unsatisfiable — skip rather than
    // minting a dead window (the roster may have been edited under the layout).
    if (v.type === "agent" && !v.agentId) continue;
    specs.push({ type: v.type as ViewType, label: v.label, specKey: key, url: v.url, port: v.port, agentId: v.agentId, dir: v.dir, command: v.command, style: v.style });
  }
  // A workspace with no declared views still gets a terminal — the daemon's default.
  if (!specs.length) specs.push({ type: "terminal" });
  return specs;
}

// Launch is minutes-long (image pull, clones); the daemon contract returns the
// record IMMEDIATELY in state "creating" and the web polls `GET /sessions/:id`,
// rendering `phase`. The work continues in the background here.
export function startSession(body: DaemonLaunchBody): SessionRecord {
  const id = `s-${randomBytes(3).toString("hex")}`;
  const rec: SessionRecord = {
    id,
    workspaceId: body.workspaceId,
    environmentId: body.environmentId,
    environmentName: body.environmentName,
    name: body.name?.trim() || undefined,
    state: "creating",
    phase: "starting container",
    ...(body.origin === "local" ? { origin: "local" as const } : {}),
    createdAt: Date.now(),
    workspaceName: body.workspace?.name,
    viewsPending: viewSpecsFrom(body).length,
    roster: parseRoster(body.agents),
    ...(typeof body.agentSecrets === "string" ? { agentSecretsSealed: body.agentSecrets } : {}),
  };
  sessions[id] = rec;
  persist();

  const req: LaunchRequest = {
    name: rec.name ?? id,
    workspaceId: body.workspaceId,
    persistence: body.persistence,
    repos: (body.workspace?.repos ?? []).map((r) => ({ url: r.url, name: r.dir, branch: r.branch })),
    authorizedKeys: body.workspace?.authorizedKeys,
    views: viewSpecsFrom(body),
    envConfig: body.envConfig,
    repoTokens: body.repoTokens,
    claude: body.claudeBlob ?? body.claude,
    vault: body.vault,
    git: body.git ?? (body.workspace?.gitIdentity?.name && body.workspace?.gitIdentity?.email ? { name: body.workspace.gitIdentity.name, email: body.workspace.gitIdentity.email } : undefined),
    metadata: { sessionId: id },
    // Build logs ride the phase string — strip control chars and cap it so the record
    // stays clean JSON and the web's status line stays one line.
    onPhase: (phase) => update(id, { phase: phase.replace(/[\x00-\x1f\x7f]/g, " ").trim().slice(0, 160) }),
    // The roster is live from the moment the sandbox exists: agent views are scaffolded during
    // the launch and their chat page asks for its agent right away.
    onSandbox: (sandboxId) => {
      update(id, { sandboxId });
      if (rec.roster?.length) registerRoster(rec.workspaceId ?? id, id, sandboxId, rec.roster);
      // The agents' own credentials (each its gateway slot) — honored now (PLAN §5 P1).
      const secrets = parseAgentSecrets(sealedOrInline(body.agentSecrets));
      if (secrets.length) setAgentCredentials(id, secrets);
    },
  };

  void launch(req)
    .then((out) => {
      update(id, { sandboxId: out.sandbox.id, state: "ready", phase: undefined, viewsPending: 0, ...(out.vault ? { vault: out.vault } : {}) });
      log(`${id} ready (sandbox ${out.sandbox.id.slice(0, 8)})${rec.roster?.length ? `, ${rec.roster.length} agent(s)` : ""}`);
    })
    .catch((e: Error) => {
      // The record carries a sandboxId from onSandbox, so the failure path owes the same
      // cleanup finishSession does: views scaffolded before the failure would otherwise stay
      // addressable (and listed to the web) pointing at a sandbox the launch already deleted.
      const dead = sessions[id]?.sandboxId;
      update(id, { state: "error", error: e.message, phase: undefined, viewsPending: 0 });
      if (dead) {
        dropViewsForSandbox(dead);
        dropSink(dead);
        forgetThreads(dead);
      }
      // The roster is registered as soon as the sandbox exists (onSandbox), so a launch that
      // dies later must un-register it — otherwise the agents (and their credentials) stay
      // live in memory pointing at a sandbox the launch already tore down.
      dropSessionAgents(id);
      log(`${id} failed: ${e.message}`);
    });
  return rec;
}

export async function finishSession(id: string): Promise<void> {
  const s = sessions[id];
  if (!s) return;
  if (s.sandboxId) {
    await deleteSandbox(s.sandboxId).catch(() => undefined);
    dropViewsForSandbox(s.sandboxId);
    dropSink(s.sandboxId);
    forgetThreads(s.sandboxId);
  }
  dropSessionAgents(id);
  delete sessions[id];
  persist();
}

export function renameSession(id: string, name: string): SessionRecord | undefined {
  update(id, { name: name.trim() || undefined });
  return sessions[id];
}

// --- daemon-shaped projections -------------------------------------------------

export function sessionJson(s: SessionRecord): Record<string, unknown> {
  return {
    id: s.id,
    workspaceId: s.workspaceId ?? "",
    ...(s.environmentId ? { environmentId: s.environmentId } : {}),
    ...(s.environmentName ? { environmentName: s.environmentName } : {}),
    ...(s.name ? { name: s.name } : {}),
    state: s.state,
    ...(s.error ? { error: s.error } : {}),
    ...(s.phase ? { phase: s.phase } : {}),
    // The daemon contract pieces the CLI reads: ISO createdAt, origin scoping,
    // the inline workspace name, and views-progress (pending counts down to 0).
    createdAt: new Date(s.createdAt).toISOString(),
    ...(s.origin ? { origin: s.origin } : {}),
    ...(s.workspaceName ? { workspace: { name: s.workspaceName } } : {}),
    viewsProgress: { pending: s.viewsPending ?? 0, skipped: [] },
    // What the sidecar holds (names + revision, never values) — the caller re-mints a manifest
    // and calls `start` again when it reads revision 0 (PLAN §5b). Without it here that
    // contract is unreachable: nothing else surfaces the record's vault summary.
    ...(s.vault ? { vault: s.vault } : {}),
  };
}

// Pause/resume a session by pausing its sandbox (OpenSandbox keeps state; views'
// processes stop with it and revive on resume). Local mode's `--pause/--resume`.
export async function pauseSession(id: string): Promise<SessionRecord | undefined> {
  const s = sessions[id];
  if (!s?.sandboxId) return undefined;
  if (s.state !== "stopped") {
    const { pauseSandbox } = await import("./opensandbox.js");
    await pauseSandbox(s.sandboxId);
    update(id, { state: "stopped" });
  }
  return sessions[id];
}
// `vaultBlob` (optional, sealed) = a FRESH manifest minted for this resume. Docker
// pause/resume keeps the sidecar's vault, but a sidecar restart or snapshot-restore loses
// it — so with a manifest we always re-install (new scoped tokens, the old ones are the
// minter's to revoke); without one we only report whether the vault is still there
// (revision 0 = gone; the caller can re-mint and call again).
export async function resumeSession(id: string, vaultBlob?: unknown): Promise<SessionRecord | undefined> {
  const s = sessions[id];
  if (!s?.sandboxId) return undefined;
  if (s.state === "stopped") {
    const { resumeSandbox } = await import("./opensandbox.js");
    await resumeSandbox(s.sandboxId);
    update(id, { state: "ready" });
  }
  const manifest = vaultBlob !== undefined ? parseVaultManifest(sealedOrInline(vaultBlob)) : undefined;
  if (manifest) {
    // Same policy as the launch (launch.ts): a manifest the sidecar won't take degrades the
    // resume instead of killing it — but the record must then say the vault is GONE (revision
    // 0), never keep reporting the revision of an install that no longer exists.
    try {
      update(id, { vault: await installVault(s.sandboxId, manifest) });
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      log(`${id}: credential vault re-install failed — continuing without it: ${msg}`);
      update(id, { vault: { revision: 0, credentials: manifest.credentials.map((c) => c.name), bindings: [`install failed: ${msg.slice(0, 200)}`] } });
    }
  } else if (s.vault && s.vault.revision > 0 && !(await vaultPresent(s.sandboxId))) {
    log(`${id}: credential vault lost across resume — needs a fresh manifest`);
    update(id, { vault: { ...s.vault, revision: 0 } });
  }
  return sessions[id];
}

// The daemon View shape the web renders: target.port is informational here (the
// data plane rides /v/:id through the doorman either way).
export function viewJson(v: View, sessionId: string): Record<string, unknown> {
  return {
    id: v.id,
    sessionId,
    type: v.type,
    target: { port: v.port, ...(v.dir ? { dir: v.dir } : v.type === "directory" ? { dir: "/" } : {}), ...(v.command ? { command: v.command } : {}), ...(v.type === "agent" && v.agentId ? { agentId: v.agentId } : {}), ...(v.type === "web" ? { appPort: v.appPort ?? v.port, ...(v.appPath ? { appPath: v.appPath } : {}), url: webUrl(v) } : {}) },
    ...(v.label ? { label: v.label } : {}),
    ...(v.specKey ? { specKey: v.specKey } : {}),
    ...(v.style ? { style: v.style } : {}),
  };
}

// A web view's public address: its slug as a hostname — on the wildcard sandbox domain
// when the cloud injected one, else `<slug>.localhost` (loopback in every browser).
function webUrl(v: View): string {
  const path = v.appPath ?? "/";
  const domain = getSandbox()?.domain;
  return domain ? `https://${v.slug}.${domain}${path}` : `http://${v.slug}.localhost:${PORT}${path}`;
}

export function sessionViews(s: SessionRecord): View[] {
  return s.sandboxId ? viewsForSandbox(s.sandboxId) : [];
}

// Live view creation on a ready session (the session screen's "add view").
export async function createSessionView(s: SessionRecord, spec: ViewSpec): Promise<View | undefined> {
  if (!s.sandboxId) return undefined;
  return scaffoldView(s.sandboxId, spec);
}

// SessionChanges via execd git — real numbers, not a stub: dirty/files from
// `status --porcelain`, ahead = commits on the session branch main hasn't merged.
export async function sessionChanges(s: SessionRecord): Promise<Record<string, unknown>> {
  const empty = { dirty: false, ahead: 0, behind: 0, merging: false, files: [] as unknown[] };
  if (!s.sandboxId || !sinkFor(s.sandboxId)) return empty;
  try {
    const st = await run(s.sandboxId, "git status --porcelain", { cwd: "/workspace", timeoutMs: 30_000 });
    const files = st.stdout
      .split("\n")
      .filter(Boolean)
      .map((l) => ({ status: l.slice(0, 2).trim() || "??", path: l.slice(3) }));
    const ahead = await run(s.sandboxId, "git rev-list --count main..HEAD", { cwd: "/workspace", timeoutMs: 30_000 });
    return { dirty: files.length > 0, ahead: Number(ahead.stdout.trim()) || 0, behind: 0, merging: false, files };
  } catch {
    return empty;
  }
}
