// The daemon-compatible session surface (PLAN O3). The web's DaemonClient drives
// every server through one wire contract; isogate implements the core of it —
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
import { dropSessionAgents, parseRoster, registerRoster, type AgentDef } from "./agents.js";

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
}

let sessions: Record<string, SessionRecord> = {};
try {
  sessions = JSON.parse(readFileSync(FILE, "utf8")) as Record<string, SessionRecord>;
} catch {
  sessions = {};
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

// --- the daemon launch body → isogate launch ----------------------------------

// What the web actually sends POST /sessions (the subset isogate honors; unknown
// fields — agent, harnesses, claude — are accepted and ignored for now).
export interface DaemonLaunchBody {
  workspace?: {
    name?: string;
    repos?: { url?: string; dir?: string; branch?: string }[];
    defaultViews?: Record<string, { type?: string; label?: string; dir?: string; url?: string; port?: number }>;
    gitIdentity?: { name?: string; email?: string };
  };
  workspaceId?: string;
  environmentId?: string;
  environmentName?: string;
  persistence?: unknown;
  envConfig?: unknown;
  repoTokens?: unknown;
  git?: { name?: string; email?: string };
  name?: string;
  origin?: string;
  agents?: unknown; // the workspace's agent roster (PLAN O5); parsed via parseRoster
}

const VIEW_TYPES = new Set(["terminal", "code", "directory", "web"]);

function viewSpecsFrom(body: DaemonLaunchBody): ViewSpec[] {
  const specs: ViewSpec[] = [];
  for (const [key, v] of Object.entries(body.workspace?.defaultViews ?? {})) {
    if (!v?.type || !VIEW_TYPES.has(v.type)) continue;
    specs.push({ type: v.type as ViewType, label: v.label, specKey: key, url: v.url, port: v.port });
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
  };
  sessions[id] = rec;
  persist();

  const req: LaunchRequest = {
    name: rec.name ?? id,
    workspaceId: body.workspaceId,
    persistence: body.persistence,
    repos: (body.workspace?.repos ?? []).map((r) => ({ url: r.url, name: r.dir, branch: r.branch })),
    views: viewSpecsFrom(body),
    envConfig: body.envConfig,
    repoTokens: body.repoTokens,
    git: body.git ?? (body.workspace?.gitIdentity?.name && body.workspace?.gitIdentity?.email ? { name: body.workspace.gitIdentity.name, email: body.workspace.gitIdentity.email } : undefined),
    metadata: { sessionId: id },
    // Build logs ride the phase string — strip control chars and cap it so the record
    // stays clean JSON and the web's status line stays one line.
    onPhase: (phase) => update(id, { phase: phase.replace(/[\x00-\x1f\x7f]/g, " ").trim().slice(0, 160) }),
  };

  void launch(req)
    .then((out) => {
      update(id, { sandboxId: out.sandbox.id, state: "ready", phase: undefined, viewsPending: 0 });
      if (rec.roster?.length) registerRoster(rec.workspaceId ?? id, id, out.sandbox.id, rec.roster);
      log(`${id} ready (sandbox ${out.sandbox.id.slice(0, 8)})${rec.roster?.length ? `, ${rec.roster.length} agent(s)` : ""}`);
    })
    .catch((e: Error) => {
      update(id, { state: "error", error: e.message, phase: undefined, viewsPending: 0 });
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
export async function resumeSession(id: string): Promise<SessionRecord | undefined> {
  const s = sessions[id];
  if (!s?.sandboxId) return undefined;
  if (s.state === "stopped") {
    const { resumeSandbox } = await import("./opensandbox.js");
    await resumeSandbox(s.sandboxId);
    update(id, { state: "ready" });
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
    target: { port: v.port, ...(v.type === "directory" ? { dir: "/" } : {}), ...(v.type === "web" ? { appPort: v.appPort ?? v.port, ...(v.appPath ? { appPath: v.appPath } : {}), url: webUrl(v) } : {}) },
    ...(v.label ? { label: v.label } : {}),
    ...(v.specKey ? { specKey: v.specKey } : {}),
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
