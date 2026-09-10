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
import { DATA, HOST, PORT, ensureDataDir, getSandbox } from "./config.js";
import { authorizedKeysFile, installAuthorizedKeys, installBastionKey, launch, parseAuthorizedKey, scaffoldView, startSshAccess, type LaunchRequest, type ViewSpec } from "./launch.js";
import { deleteSandbox } from "./opensandbox.js";
import { closeSsh, openSsh } from "./sshfwd.js";
import { bastion, modeForView, sshCommandFor, CONTAINER_SSH_PORT } from "./bastion.js";
import { run } from "./execd.js";
import { dropSink, sinkFor } from "./persistence.js";
import { dropLocksForSandbox } from "./webdav.js";
import { davPassword, dropViewsForSandbox, ensureRouteId, viewsForSandbox, type View, type ViewType } from "./views.js";
import { dropSessionAgents, parseAgentSecrets, parseRoster, registerRoster, setAgentCredentials, type AgentDef } from "./agents.js";
import { installVault, parseVaultManifest, vaultPresent, type VaultSummary } from "./vault.js";
import { forgetThreads } from "./threads.js";
import { chatCommand } from "./acpview.js";
import { sealedOrInline } from "./envelope.js";

const log = (...a: unknown[]) => console.log("[sessions]", ...a);
const FILE = join(DATA, "sessions.json");

export type SessionState = "creating" | "ready" | "stopped" | "error";

export interface SessionRecord {
  id: string; // s-xxxxxx — what the web sees
  sandboxId?: string; // set once the sandbox exists
  // WHO launched it — the actor id the Worker proxy stamped on the POST /sessions (x-isolation-actor).
  // A session is its launcher's: every session/view/sandbox call is answered for the owner only, and
  // an org owner/admin may just list + delete (mayOpen / mayTearDown below). Absent on a session
  // launched without the proxy (local / direct use) — such a session is open to the token holder.
  owner?: string;
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
  // The port `ssh -p` reaches this session on, when ssh is open for it (a key was installed AND
  // sshd came up). Absent = no ssh; the web shows the command only when this is set.
  sshPort?: number;
  // Whether sshd really came up INSIDE the sandbox (launch.ts `out.ssh`). Distinct from `sshPort`,
  // which records a forwarder THIS process binds and therefore drops on every restart: the bastion
  // hop does not use that forwarder at all, so "can this session be reached over ssh?" has to be
  // answered from something that survives a restart. `undefined` = a record written before the
  // field existed, i.e. unknown — never read as "no".
  sshd?: boolean;
  // The member's PUBLIC keys, kept so a bastion route can be registered (or re-registered on a
  // reconnect) long after the launch body is gone. Public keys — nothing here is a secret.
  authorizedKeys?: string[];
  // Which of those keys were authorized AFTER the launch, by fingerprint (`ssh-keys` API). A
  // session-only grant: it is not a credential on anybody's account, it is never written back to
  // the workspace, and it dies with this session. The map exists so the list can say where a key
  // came from — an account key comes back on the next launch, one of these does not.
  addedKeys?: Record<string, { addedAt: number; via?: string }>;
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

// ssh forwarders are bound by THIS process (sshfwd.ts), so a persisted `sshPort` is a lie the
// moment the server restarts — and a dangerous one: the next launch is handed a port from the
// bottom of the same range, so a saved `ssh -p 22200` command would open a shell in a DIFFERENT
// session's sandbox. Drop every persisted port on boot, then re-open a forwarder for each session
// whose sandbox is still around (the in-sandbox bridge outlives this process) and let it publish
// whatever port it actually got.
{
  const reopen: SessionRecord[] = [];
  let cleared = false;
  for (const rec of Object.values(sessions)) {
    if (rec.sshPort === undefined) continue;
    delete rec.sshPort;
    cleared = true;
    if (rec.sandboxId && rec.state !== "error") reopen.push(rec);
  }
  if (cleared) persist();
  if (reopen.length) {
    void (async () => {
      for (const rec of reopen) {
        const port = rec.sandboxId ? await openSsh(rec.id, rec.sandboxId).catch(() => null) : null;
        if (!port) continue;
        // The session can have been finished while the bind was in flight; `update` would then be
        // a silent no-op and the listener would sit on a port out of a 100-wide range forever.
        if (sessions[rec.id]) update(rec.id, { sshPort: port });
        else closeSsh(rec.id);
      }
    })();
  }
}

// The bastion mints a FRESH agent keypair per control connection, so on every (re)connect the
// sandboxes already running trust a key that is no longer the one it will dial with. Install the
// new one wherever a session is live — otherwise every existing session goes ssh-dark after a
// bastion redeploy, which is exactly the reconnect the soft-state design is meant to survive.
bastion.onAgentKeyRotated((publicKey) => {
  void (async () => {
    const { installBastionKey } = await import("./launch.js");
    for (const rec of Object.values(sessions)) {
      if (!rec.sandboxId || rec.state !== "ready") continue;
      await installBastionKey(rec.sandboxId, publicKey).catch(() => undefined);
      syncRoutes(rec.id, rec.sandboxId);
    }
  })();
});

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

// --- who is asking (2026-09-08) --------------------------------------------------------
// The master token says "some member of the org this server belongs to"; the Worker proxy adds
// WHICH one (`x-isolation-actor`) and their org role (`x-isolation-actor-role`). Only the proxy can
// set them — the server has no public URL, and the proxy drops any copy a client sends — so they
// are trusted as-is. No header at all = the token holder is using the server directly (local
// mode, self-host), which stays as open as it always was.
export interface Actor {
  id: string;
  manages: boolean; // org owner/admin — may list + tear down anyone's session, never open it
}
export function actorFrom(headers: Record<string, string | string[] | undefined>): Actor | undefined {
  const id = headers["x-isolation-actor"];
  if (typeof id !== "string" || !id) return undefined;
  const role = headers["x-isolation-actor-role"];
  return { id, manages: role === "owner" || role === "admin" };
}
// May this actor OPEN the session — read its state, mint its view tokens, drive its sandbox?
// Only its launcher (or anyone, when the session or the request carries no identity).
export const mayOpen = (actor: Actor | undefined, s: SessionRecord | undefined): boolean => !actor || !s?.owner || s.owner === actor.id;
// May this actor SEE it in a list and DELETE it? The launcher, plus the org's owners/admins — the
// ops right that lets whoever pays for a metered server stop a forgotten session on it.
export const mayTearDown = (actor: Actor | undefined, s: SessionRecord | undefined): boolean => mayOpen(actor, s) || !!actor?.manages;

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
export function startSession(body: DaemonLaunchBody, owner?: string): SessionRecord {
  const id = `s-${randomBytes(3).toString("hex")}`;
  const rec: SessionRecord = {
    id,
    ...(owner ? { owner } : {}),
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
    ...(Array.isArray(body.workspace?.authorizedKeys) ? { authorizedKeys: body.workspace.authorizedKeys.filter((k) => typeof k === "string") } : {}),
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
    // What the SANDBOX trusts when a user arrives through the bastion (bastion.ts): their own key
    // was already checked at the edge, so this is the only key the container needs.
    bastionKey: bastion.agentPublicKey(),
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
    .then(async (out) => {
      // ssh rides a per-session TCP forwarder (sshfwd.ts) — opened only when the launch actually
      // brought sshd up, so `sshPort` present means "this really answers".
      const sshPort = out.ssh ? await openSsh(id, out.sandbox.id).catch(() => null) : null;
      // The bastion's routes: one per ssh-shaped view, so a user types `ssh <routeId>@<host>` and
      // never learns an address. Registered only when the sandbox really has an sshd to reach.
      if (out.ssh) syncRoutes(id, out.sandbox.id);
      // `finishSession` can land while the launch is still finishing: it already closed a
      // forwarder that did not exist yet, so the one just bound is ours to take back down. Same
      // for the routes just published — the record is gone, so nothing else will ever unregister
      // them, and the bastion would go on advertising ssh into a sandbox nobody owns.
      if (!sessions[id]) {
        bastion.unregisterSandbox(out.sandbox.id);
        if (sshPort) closeSsh(id);
      }
      update(id, { sandboxId: out.sandbox.id, state: "ready", phase: undefined, viewsPending: 0, sshd: Boolean(out.ssh), ...(out.vault ? { vault: out.vault } : {}), ...(sshPort ? { sshPort } : {}) });
      log(`${id} ready (sandbox ${out.sandbox.id.slice(0, 8)})${rec.roster?.length ? `, ${rec.roster.length} agent(s)` : ""}`);
    })
    .catch(async (e: Error) => {
      // The record carries a sandboxId from onSandbox, so the failure path owes the same
      // cleanup finishSession does: views scaffolded before the failure would otherwise stay
      // addressable (and listed to the web) pointing at a sandbox the launch already deleted.
      const dead = sessions[id]?.sandboxId;
      update(id, { state: "error", error: e.message, phase: undefined, viewsPending: 0 });
      closeSsh(id);
      if (dead) {
        // A view added while the launch was still running registered its bastion route already;
        // the views go below, and a route whose view is gone can never be unregistered by id.
        bastion.unregisterSandbox(dead);
        // AWAITED: a pump is keyed by VIEW id and `stopToolPumpsFor` finds them THROUGH the
        // sandbox's views — the lazy import yields, so a fire-and-forget call would run after
        // `dropViewsForSandbox` had already emptied the list and would stop nothing at all.
        await stopPumps(dead);
        dropViewsForSandbox(dead);
        dropLocksForSandbox(dead); // the mount is gone with the sandbox
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

// The control channel's pumps (PLAN §1 I3) are stopped whenever a sandbox stops existing or
// pauses. Imported lazily on purpose: toolpump reads THIS module's session records, and a static
// import both ways is a module cycle — which is exactly how bastion's constants ended up being
// read before they were initialized.
const stopPumps = async (sandboxId: string): Promise<void> => {
  const { stopToolPumpsFor } = await import("./toolpump.js");
  stopToolPumpsFor(sandboxId);
};

export async function finishSession(id: string): Promise<void> {
  const s = sessions[id];
  if (!s) return;
  // A chat bound to this session OUTLIVES it (PLAN §1 I3, owner call): it says the session ended
  // and its agents stop answering, rather than the channel vanishing with the compute. Best-effort
  // and NOT awaited: the goodbye is a call to the cloud with a 20s timeout, and a chat we cannot
  // reach must not hold up the teardown. (channels.ts reads session records, so the import is
  // dynamic — which means the bindings flip to "ended" a tick from now, not synchronously.)
  void import("./channels.js")
    .then((m) => m.endChannelsFor(id))
    .catch(() => undefined);
  // Before the sandbox goes: the listener would otherwise stay open on a port pointing at nothing,
  // and the bastion would keep advertising routes into a sandbox that no longer exists.
  closeSsh(id);
  if (s.sandboxId) bastion.unregisterSandbox(s.sandboxId);
  if (s.sandboxId) {
    await stopPumps(s.sandboxId); // stop polling a bridge that is about to stop existing
    await deleteSandbox(s.sandboxId).catch(() => undefined);
    dropViewsForSandbox(s.sandboxId);
    dropLocksForSandbox(s.sandboxId);
    dropSink(s.sandboxId);
    forgetThreads(s.sandboxId);
  }
  dropSessionAgents(id);
  (await import("./channels.js")).forgetEnvelopesFor(id);
  delete sessions[id];
  persist();
}

/**
 * The end-user public keys the bastion will accept for a session — the SAME wire-input treatment
 * the in-sandbox authorized_keys file gets, for the same reason: this list is an authentication
 * allow-list, and a "key" carrying a newline would smuggle extra entries into whatever the bastion
 * writes it into. The bastion is SHARED across every server on the cloud, so a bad entry there is
 * not even our own tenant's problem — never send one.
 *
 * Empty means nobody at all can open the route, so a caller must not hand out an `ssh` command:
 * the only answer it could ever get is "permission denied".
 */
export function sshKeysFor(sessionId: string): string[] {
  return authorizedKeysFile(sessions[sessionId]?.authorizedKeys).split("\n").filter(Boolean);
}

// --- ssh keys on a LIVE session -----------------------------------------------------------------
//
// Letting somebody in — a colleague pairing for an hour, a laptop whose key is not on the account,
// an agent that wants its own way back in — used to mean editing the account's credentials and
// launching the session again, which throws away the very state the visitor was invited to see.
// These three take effect on a RUNNING session: the file inside the sandbox and the bastion's
// allow-list are both rewritten from the record, and nothing restarts.
//
// The grant is the SESSION's, deliberately: no credential is created, nothing is written back to
// the workspace, and it is gone when the session finishes (BACKLOG has the "promote to account
// key" follow-up). A key added here is exactly as powerful as one from the account — this is a
// shell in the sandbox — so the list says where each key came from and any of them can be revoked.

/** One authorized key, as a caller should see it: never the blob, always the fingerprint. */
export interface SessionKeyInfo {
  fingerprint: string;
  type: string;
  comment: string;
  /** `account` = came with the launch (and comes back on the next one); `session` = added here. */
  source: "account" | "session";
  addedAt?: number;
  via?: string;
}

function keyInfo(rec: SessionRecord, line: string): SessionKeyInfo | undefined {
  const k = parseAuthorizedKey(line);
  if (!k) return undefined;
  const added = rec.addedKeys?.[k.fingerprint];
  return { fingerprint: k.fingerprint, type: k.type, comment: k.comment, source: added ? "session" : "account", ...(added ? { addedAt: added.addedAt, ...(added.via ? { via: added.via } : {}) } : {}) };
}

export function listSessionKeys(sessionId: string): SessionKeyInfo[] {
  const rec = sessions[sessionId];
  if (!rec) return [];
  return (rec.authorizedKeys ?? []).map((l) => keyInfo(rec, l)).filter((k): k is SessionKeyInfo => !!k);
}

/**
 * Push the record's allow-list into the running sandbox AND out to the bastion — the two places a
 * key has to be for `ssh` to work — and bring sshd up if this is the first key the session ever
 * had (a launch with no key never started it: launch.ts).
 *
 * Throws when the sandbox refuses the write: the caller is a person who just pasted a key and is
 * about to try it, so "added" has to mean it actually works.
 */
async function applyKeys(rec: SessionRecord): Promise<boolean> {
  if (!rec.sandboxId) throw new Error("this session has no sandbox yet");
  const keys = rec.authorizedKeys ?? [];
  // clearWhenEmpty: revoking the LAST key must truncate the file, or the key just revoked would go
  // on working for the life of the sandbox.
  if (!(await installAuthorizedKeys(rec.sandboxId, keys, undefined, { clearWhenEmpty: true }))) {
    throw new Error("the sandbox would not accept the key — it may be starting up or asleep");
  }
  // sshd was never started for a session that launched without a key and without a bastion. Now
  // there is a reason for it, so start it — that is what makes this work with no relaunch.
  if (rec.sshd !== true && keys.length) {
    // The bastion's agent key is the OTHER half of the edge hop: the end user's key is verified at
    // the bastion, and THIS is what the container itself trusts (launch.ts). A launch that never
    // called `startSshAccess` never installed it either — and `syncRoutes` below is about to
    // publish a route — so put it in first, or the route would be a command whose only possible
    // answer is "permission denied".
    const agentKey = bastion.agentPublicKey();
    if (agentKey) await installBastionKey(rec.sandboxId, agentKey);
    const up = await startSshAccess(rec.sandboxId);
    update(rec.id, { sshd: up });
    if (up) {
      const port = await openSsh(rec.id, rec.sandboxId).catch(() => null);
      if (port && sessions[rec.id]) update(rec.id, { sshPort: port });
    }
  }
  syncRoutes(rec.id, rec.sandboxId);
  return sessions[rec.id]?.sshd === true;
}

/**
 * Apply the record's list, and leave the record listing EVERY key that might now be in the sandbox
 * if the push failed — the union of what it said before and what it says after.
 *
 * The record is written first (it is what `listSessionKeys` and the bastion read), so a failed push
 * leaves the two disagreeing, and only one direction of disagreement is safe. A list that shows a
 * key the sandbox will not let in is a cosmetic lie the next revoke clears. A list that OMITS a key
 * the sandbox does let in is the dangerous one: it opens a shell for the life of the session while
 * being invisible and un-revokable, because the next DELETE answers "no key with that fingerprint".
 *
 * And a failure genuinely cannot say which happened: `installAuthorizedKeys` reports a command that
 * ran and failed the same way as one that never ran, and a dropped connection AFTER the sandbox
 * wrote the file looks identical to one before. So the union is the only shape that is always safe
 * — for a failed add and a failed revoke alike — and both are retried simply by asking again.
 */
async function pushKeys(sessionId: string, before: Pick<SessionRecord, "authorizedKeys" | "addedKeys">): Promise<boolean> {
  try {
    return await applyKeys(sessions[sessionId]!);
  } catch (e) {
    const rec = sessions[sessionId];
    if (rec) {
      const merged = new Map<string, string>();
      for (const line of [...(before.authorizedKeys ?? []), ...(rec.authorizedKeys ?? [])]) {
        const p = parseAuthorizedKey(line);
        if (p) merged.set(p.fingerprint, p.line);
      }
      update(sessionId, {
        authorizedKeys: [...merged.values()],
        // Keep the provenance of anything that comes back, so a key restored by this path is still
        // labelled `session` rather than quietly reading as one the account carries.
        addedKeys: { ...(rec.addedKeys ?? {}), ...(before.addedKeys ?? {}) },
      });
    }
    throw e;
  }
}

export async function authorizeSessionKey(sessionId: string, input: unknown, via?: string): Promise<{ key: SessionKeyInfo; keys: SessionKeyInfo[]; ssh: boolean }> {
  const rec = sessions[sessionId];
  if (!rec) throw new Error("unknown session");
  if (rec.state !== "ready") throw new Error(rec.state === "stopped" ? "this session is asleep — resume it and add the key then" : "this session is not ready yet");
  const k = parseAuthorizedKey(input);
  if (!k) throw new Error("that is not an ssh public key — paste one line, the contents of a .pub file (`ssh-ed25519 AAAA… you@laptop`)");
  const before = { authorizedKeys: rec.authorizedKeys, addedKeys: rec.addedKeys };
  const current = (rec.authorizedKeys ?? []).map((l) => parseAuthorizedKey(l)).filter((p): p is NonNullable<typeof p> => !!p);
  // ALREADY THERE IS SUCCESS, not an error: re-pasting the same key (or one the account already
  // carries) is somebody making sure, and the honest answer is that it is authorized.
  const dup = current.find((p) => p.blob === k.blob);
  if (!dup) {
    if (current.length >= 50) throw new Error("this session already has 50 authorized keys — revoke one first");
    update(sessionId, {
      authorizedKeys: [...current.map((p) => p.line), k.line],
      addedKeys: { ...(rec.addedKeys ?? {}), [k.fingerprint]: { addedAt: Date.now(), ...(via ? { via: via.slice(0, 60) } : {}) } },
    });
  }
  const ssh = await pushKeys(sessionId, before);
  const keys = listSessionKeys(sessionId);
  return { key: keys.find((x) => x.fingerprint === k.fingerprint) ?? keyInfo(sessions[sessionId]!, k.line)!, keys, ssh };
}

export async function revokeSessionKey(sessionId: string, fingerprint: unknown): Promise<{ revoked: SessionKeyInfo; keys: SessionKeyInfo[] }> {
  const rec = sessions[sessionId];
  if (!rec) throw new Error("unknown session");
  if (rec.state !== "ready") throw new Error(rec.state === "stopped" ? "this session is asleep — resume it to change its keys" : "this session is not ready yet");
  const want = String(fingerprint ?? "").trim();
  const gone = listSessionKeys(sessionId).find((k) => k.fingerprint === want);
  if (!gone) throw new Error("this session has no key with that fingerprint");
  const before = { authorizedKeys: rec.authorizedKeys, addedKeys: rec.addedKeys };
  const addedKeys = { ...(rec.addedKeys ?? {}) };
  delete addedKeys[want];
  update(sessionId, {
    authorizedKeys: (rec.authorizedKeys ?? []).filter((l) => parseAuthorizedKey(l)?.fingerprint !== want),
    addedKeys,
  });
  await pushKeys(sessionId, before);
  return { revoked: gone, keys: listSessionKeys(sessionId) };
}

// Register a bastion route for every ssh-shaped view of a sandbox — terminal views, which attach
// their live tmux session, agent views, which join their live conversation, and code views, whose
// transparent shell is what a local IDE drives (see `modeForView`). Idempotent: a route id is
// minted once and persisted on the view, so re-running this re-asserts rather than churns, and a
// saved `ssh <id>@host` keeps working across restarts of anything.
// The tmux session a terminal view runs in — the bastion `attach`es exactly this, so an ssh user
// and the browser terminal share one live screen rather than getting two separate shells.
function tmuxTargetFor(v: View): string {
  return `iso-view-${v.id}`;
}

export function syncRoutes(sessionId: string, sandboxId: string): void {
  if (!bastion.enabled()) return;
  const keys = sshKeysFor(sessionId);
  for (const v of viewsForSandbox(sandboxId)) {
    const mode = modeForView(v.type);
    if (!mode) continue;
    // An agent route carries the command whose stdio IS the conversation. The bastion execs what it
    // is told rather than knowing anything about ACP — the same division tmux mode already has. No
    // command means no door: register nothing rather than a route the edge can only refuse.
    const chat = mode === "acp" ? chatCommand(v.port, v.id, v.label) : undefined;
    if (mode === "acp" && !chat) {
      log(`${v.id}: agent view has no usable bridge port (${String(v.port)}) — no ssh route`);
      continue;
    }
    const routeId = ensureRouteId(v.id);
    if (!routeId) continue;
    bastion.registerRoute({
      routeId,
      // The bastion echoes this back as the reverse channel's srcIP, and what we need there is the
      // SANDBOX id — that is what resolves to an endpoint.
      sessionId: sandboxId,
      viewId: v.id,
      viewType: v.type,
      mode,
      ...(mode === "tmux" ? { tmuxTarget: tmuxTargetFor(v) } : {}),
      ...(chat ? { chatCommand: chat } : {}),
      ...(v.dir ? { dir: v.dir } : {}),
      ...(v.label ? { label: v.label } : {}),
      keys,
      containerSshPort: CONTAINER_SSH_PORT,
    });
  }
}

// DELETE /sandboxes/:id kills a sandbox without going through `finishSession`, so the session's
// ssh forwarder has to be torn down here too — otherwise it stays bound (holding one of a 100-wide
// range) and the record keeps advertising an `sshPort` that answers nothing, which is exactly what
// the field's "present means this really answers" contract promises it never does.
export function dropSshForSandbox(sandboxId: string): void {
  bastion.unregisterSandbox(sandboxId);
  const s = sessionForSandbox(sandboxId);
  if (!s) return;
  closeSsh(s.id);
  if (s.sshPort !== undefined) {
    delete s.sshPort;
    persist();
  }
}

export function renameSession(id: string, name: string): SessionRecord | undefined {
  update(id, { name: name.trim() || undefined });
  return sessions[id];
}

// --- daemon-shaped projections -------------------------------------------------

export function sessionJson(s: SessionRecord): Record<string, unknown> {
  return {
    id: s.id,
    ...(s.owner ? { owner: s.owner } : {}), // so an admin's org-wide list can say whose it is
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
    // The port `ssh -p` reaches this session on. Present only when ssh really answers (a key was
    // installed, sshd came up, the bridge is listening and a forwarder is bound), so the web can
    // show the command on its presence alone.
    ...(s.sshPort ? { sshPort: s.sshPort } : {}),
  };
}

// Pause/resume a session by pausing its sandbox (OpenSandbox keeps state; views'
// processes stop with it and revive on resume). Local mode's `--pause/--resume`.
export async function pauseSession(id: string): Promise<SessionRecord | undefined> {
  const s = sessions[id];
  if (!s?.sandboxId) return undefined;
  if (s.state !== "stopped") {
    const { pauseSandbox } = await import("./opensandbox.js");
    // The bridges stop with the sandbox, so polling them would only burn retries until the pumps
    // gave up. They come back on resume.
    await stopPumps(s.sandboxId);
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
    await (await import("./toolpump.js")).startToolPumpsFor(s.sandboxId); // the agents can reach out again (PLAN §1 I3)
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
    // How to reach this view over ssh, when there is a bastion and the view is ssh-shaped. A
    // routeId, never an address: the whole point is that no host IP or port reaches a user.
    ...sshJson(v),
    // …and how to MOUNT a files view as a drive (webdav.ts).
    ...davJson(v),
  };
}

// Any name works — the password is the whole credential — so it is a fixed, recognisable one: it
// labels the entry a keychain saves and tells a person which mount they are looking at.
const DAV_USERNAME = "isolation";

/**
 * The files view's external door, as the VIEWS LIST reports it: that a mount exists, and where.
 *
 * No credential here. This list is polled for as long as a session screen is open, so the password
 * is revealed once, on the explicit `POST …/connect` a person triggers (davConnect below) — the same
 * shape the ssh door has, where the list carries the route and the connect call carries the way in.
 */
function davJson(v: View): Record<string, unknown> {
  if (v.type !== "directory") return {};
  return { dav: { protocol: "webdav", path: davPath(v) } };
}

// The name the mounted drive gets. It is NOT cosmetic and it is not ours to choose freely: macOS
// names a WebDAV volume after the LAST PATH SEGMENT of the address it mounted (verified — mounting
// `…/dav/src/` produces `/Volumes/src`), and Windows shows the same segment as the drive label. A
// share addressed at `/v/<id>/dav/` therefore appears in Finder's sidebar, on the Desktop and in
// every `/Volumes` path as **dav** — which says nothing about which folder of which session it is.
// So the address ends in the folder's own name instead, and the drive reads as `cv`.
const mountName = (v: View): string => {
  const base = (v.dir ?? "").split("/").filter(Boolean).pop() ?? "";
  return base.replace(/[^A-Za-z0-9._-]/g, "-").replace(/^[.-]+/, "").slice(0, 40) || "workspace";
};

// `/mnt/<name>` is the mount's canonical prefix; the name is decorative, so ANY single segment
// resolves to this view's root (doorman.ts DAV_PREFIX_RE) and a bookmark saved under an older name
// keeps working. `/dav/` stays an alias for the same reason — drives mounted before this existed.
const davPath = (v: View): string => `/v/${v.id}/mnt/${encodeURIComponent(mountName(v))}/`;

/**
 * Everything a person needs to MOUNT a files view as a drive — the daemon's `nativeConnect` payload
 * for `kind: "webdav"`.
 *
 * A PATH, not an absolute URL, because this server does not know the name a browser reaches it by:
 * the cloud does (its view plane is `v--<serverId>.<preview domain>`, preview.ts viewOriginFor) and
 * joins the two. `localUrl` is the exception and is only ever right for someone sitting at the
 * machine this server runs on — which for a connected server is the common case, and is also the
 * FASTEST path: straight to loopback, no tunnel, no Worker, and none of the proxy's request-size
 * ceiling on uploads.
 *
 * The password is stable for the life of the view (views.ts davPassword) rather than minted per
 * call, because a mounted drive is saved in a keychain and has to keep working: a rotating password
 * would break every mount on the next restart, and a person cannot retype one they never see again.
 */
export function davConnect(v: View, sessionId: string): Record<string, unknown> {
  const path = davPath(v);
  const password = davPassword(v.id);
  return {
    kind: "webdav",
    protocol: "webdav",
    sessionId,
    viewId: v.id,
    host: HOST,
    port: PORT,
    user: DAV_USERNAME,
    username: DAV_USERNAME,
    password,
    passwordless: false,
    path,
    share: v.dir ? `/workspace/${v.dir}` : "/workspace",
    localUrl: `http://127.0.0.1:${PORT}${path}`,
  };
}

function sshJson(v: View): Record<string, unknown> {
  const mode = modeForView(v.type);
  if (!v.sshRouteId || !mode) return {};
  // ONE LINE, whatever the view is: the route says what it opens. A terminal route attaches that
  // terminal; an agent route lands in that conversation, rendered.
  const command = sshCommandFor(v.sshRouteId);
  return command ? { ssh: { routeId: v.sshRouteId, command } } : {};
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
