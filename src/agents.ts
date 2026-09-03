// The agent supervisor (PLAN O5a, reshaped 2026-09-03: A VIEW IS THE THREAD). A session runs N
// independent agents — personas with a harness and a credential. A CONVERSATION is a THREAD,
// and a thread is an agent VIEW: its stable key names the transcript, which lives in the sandbox
// under the workspace tree (threads.ts) — many threads per agent, each one window. No shared
// room, no coordinator. Coordination + management is the control plane here (list/start/stop/
// spawn); talking happens per view (agentview.ts, the /views/:id/messages route).
//
// Harness is pluggable + agnostic (echo built-in for credential-free runs; claude-code/codex/
// goose adapters plug in the same interface).
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "./config.js";
import { getHarness, type HarnessId } from "./harness.js";
import { loadMemory, loadThread, saveThread } from "./threads.js";
import type { View } from "./views.js";

const log = (...a: unknown[]) => console.log("[agents]", ...a);
const STORE = join(HOME, "agents"); // <STORE>/<workspaceId>/<agentId>.json — stable per (workspace, agent)

export type AgentLifecycle = "always" | "lazy";
export type AgentStatus = "idle" | "running" | "stopped";

// The workspace-owned definition (the roster entry). Secrets (the identity keypair, the
// model credential) are refs resolved elsewhere — never inlined here.
export interface AgentDef {
  id: string;
  name: string;
  harness: HarnessId; // agnostic: "echo" | "claude-code" | "codex" | …
  model?: string | null;
  systemPrompt?: string; // the USER layer (base Isolation prompt is prepended at run time)
  npub?: string; // its addressable identity (public part; the nsec is a stored secret)
  lifecycle?: AgentLifecycle;
}

export interface Message {
  role: "user" | "assistant";
  text: string;
  ts: number;
  from?: string; // optional source tag (e.g. "sidebar", a connector) — routing, not identity
}

interface AgentRecord {
  def: AgentDef;
  workspaceId: string;
  sessionId: string;
  sandboxId?: string;
  status: AgentStatus;
}

// Live agents, keyed by a session-scoped runtime id (`a-…`). The DEFINITION id is stable
// per workspace; the runtime id is this instance in this session.
const live = new Map<string, AgentRecord>();

// The launch's per-agent credentials (the cloud's sealed `agentSecrets`, opened by the session
// layer): agent definition id → the env its harness runs with. With the Credential Vault the
// token is a placeholder the sidecar overwrites; the base URL is the agent's own gateway slot.
export interface AgentCredential {
  kind: string;
  provider: string;
  token: string; // a gateway token (api keys) or a placeholder (subscriptions — the sidecar holds the real one)
  baseUrl?: string;
  accountId?: string; // ChatGPT subscriptions: what Codex's auth file needs beside the (placeholder) token
}
const credentials = new Map<string, AgentCredential>(); // `${sessionId}:${agentDefId}`
export function setAgentCredentials(sessionId: string, list: { key: string; credential: AgentCredential }[]): void {
  for (const { key, credential } of list) credentials.set(`${sessionId}:${key}`, credential);
}
export function parseAgentSecrets(raw: unknown): { key: string; credential: AgentCredential }[] {
  const list = (raw as { credentials?: unknown })?.credentials;
  if (!Array.isArray(list)) return [];
  return list.flatMap((e: Record<string, unknown>) => {
    const c = e?.credential as Record<string, unknown> | undefined;
    return typeof e?.key === "string" && c && typeof c.token === "string"
      ? [{ key: e.key, credential: { kind: String(c.kind ?? "apiKey"), provider: String(c.provider ?? "anthropic"), token: c.token, baseUrl: typeof c.baseUrl === "string" ? c.baseUrl : undefined, accountId: typeof c.accountId === "string" ? c.accountId : undefined } }]
      : [];
  });
}
// The env a harness gets for an agent: its own credential, else nothing (the sandbox's own env —
// the session slot — applies). Anthropic-shaped for claude-code; OpenAI-shaped for the rest.
function envFor(sessionId: string, agentDefId: string): Record<string, string> | undefined {
  const c = credentials.get(`${sessionId}:${agentDefId}`);
  if (!c) return undefined;
  // Subscriptions are DIRECT: the sidecar injects the real OAuth Bearer at the vendor's host; the
  // harness only needs to be "logged in" with a placeholder (Claude Code: the OAuth env var;
  // Codex: an auth file the adapter writes from these).
  if (c.kind === "subscription" && c.provider !== "openai") return { CLAUDE_CODE_OAUTH_TOKEN: c.token };
  if (c.kind === "subscription") return { CODEX_SUBSCRIPTION: "1", ...(c.accountId ? { CODEX_ACCOUNT_ID: c.accountId } : {}) };
  return c.provider === "anthropic"
    ? { ANTHROPIC_API_KEY: c.token, ...(c.baseUrl ? { ANTHROPIC_BASE_URL: c.baseUrl } : {}) }
    : { OPENAI_API_KEY: c.token, ...(c.baseUrl ? { OPENAI_BASE_URL: `${c.baseUrl.replace(/\/+$/, "")}/v1` } : {}) };
}

// (The old per-server conversation files under <HOME>/agents are gone: threads live in the
// sandbox — threads.ts. STORE stays only for the legacy listing helper below.)

// --- the base Isolation system prompt (framework layer) ------------------------

// Prepended to every agent's user prompt, per-harness. Teaches the environment: the
// workspace, the tools, the collaboration model. Kept short + agnostic; a real harness
// adapter renders it into that harness's system-prompt slot.
function basePrompt(def: AgentDef): string {
  return [
    `You are "${def.name}", an autonomous agent working inside an Isolation session — an isolated container with a project checked out at /workspace.`,
    `You are one of several independent agents on this workspace; each conversation (thread) is separate. You do NOT share a chat with the others.`,
    `You coordinate ONLY through the shared files at /workspace (git) and through the structured control plane (never by chatting at another agent).`,
    `Your own instructions follow.`,
  ].join(" ");
}

export const effectiveSystemPrompt = (def: AgentDef): string => `${basePrompt(def)}\n\n${def.systemPrompt ?? ""}`.trim();

// --- lifecycle ------------------------------------------------------------------

function newAgent(workspaceId: string, sessionId: string, sandboxId: string | undefined, def: AgentDef, status: AgentStatus): AgentRecord {
  const rec: AgentRecord = {
    def: { lifecycle: "always", ...def },
    workspaceId,
    sessionId,
    sandboxId,
    status,
  };
  const runtimeId = `a-${randomBytes(5).toString("hex")}`;
  live.set(runtimeId, rec);
  return Object.assign(rec, { runtimeId }) as AgentRecord & { runtimeId: string };
}

// Register a session's roster at launch: `always` agents start; `lazy` ones are idle.
export function registerRoster(workspaceId: string, sessionId: string, sandboxId: string | undefined, roster: AgentDef[]): void {
  for (const def of roster) {
    if (!def?.id || !def?.name) continue;
    const status: AgentStatus = (def.lifecycle ?? "always") === "always" ? "running" : "idle";
    newAgent(workspaceId, sessionId, sandboxId, def, status);
    log(`${sessionId}: registered "${def.name}" (${def.harness}, ${status})`);
  }
}

const findRuntimeId = (agentId: string): string | undefined =>
  live.has(agentId) ? agentId : [...live.entries()].find(([, r]) => r.def.id === agentId)?.[0];

export const listAgents = (sessionId: string): (AgentRecord & { runtimeId: string })[] =>
  [...live.entries()].filter(([, r]) => r.sessionId === sessionId).map(([runtimeId, r]) => ({ ...r, runtimeId }));

export function getAgent(agentId: string): (AgentRecord & { runtimeId: string }) | undefined {
  const id = findRuntimeId(agentId);
  if (!id) return undefined;
  return { ...(live.get(id) as AgentRecord), runtimeId: id };
}

// Spawn a new agent into a running session (control-plane op / an agent asking for help).
// The session's workspace + sandbox ids are passed in (the caller has the session record) so the
// FIRST agent of an empty session can be created — not bootstrapped off an existing one.
export function spawnAgent(sessionId: string, workspaceId: string, sandboxId: string | undefined, def: AgentDef): (AgentRecord & { runtimeId: string }) {
  const rec = newAgent(workspaceId, sessionId, sandboxId, def, "running") as AgentRecord & { runtimeId: string };
  log(`${sessionId}: spawned "${def.name}"`);
  return rec;
}

export function startAgent(agentId: string): boolean {
  const id = findRuntimeId(agentId);
  if (!id) return false;
  (live.get(id) as AgentRecord).status = "running";
  return true;
}
export function stopAgent(agentId: string): boolean {
  const id = findRuntimeId(agentId);
  if (!id) return false;
  (live.get(id) as AgentRecord).status = "stopped";
  return true;
}

export function dropSessionAgents(sessionId: string): void {
  for (const [k, r] of live) if (r.sessionId === sessionId) live.delete(k);
  for (const k of [...credentials.keys()]) if (k.startsWith(`${sessionId}:`)) credentials.delete(k);
}

// --- the conversation turn ------------------------------------------------------

// One turn on ONE thread — the view names it. Boots a lazy/stopped agent (a message is an
// implicit start). The transcript is read from and written to the sandbox (threads.ts); the
// agent's memory note is prepended to its prompt. Independent per thread.
export async function sendMessage(view: View, text: string, from = "view"): Promise<{ reply: Message } | { error: string }> {
  const rec = agentForView(view);
  if (!rec) return { error: "this view has no agent" };
  if (!rec.sandboxId) return { error: "session has no sandbox yet" };
  if (rec.status !== "running") rec.status = "running"; // a message starts a lazy/stopped agent
  const thread = await loadThread(rec.sandboxId, threadKeyOf(view), rec.def.id);
  const user: Message = { role: "user", text, ts: Date.now(), from };
  thread.messages.push(user);
  try {
    const harness = getHarness(rec.def.harness);
    const memory = await loadMemory(rec.sandboxId, rec.def.id);
    const out = await harness.runTurn({
      systemPrompt: `${effectiveSystemPrompt(rec.def)}${memory ? `\n\nYour memory for this workspace:\n${memory}` : ""}`,
      history: thread.messages.slice(0, -1),
      userText: text,
      agent: { id: rec.def.id, name: rec.def.name, model: rec.def.model ?? undefined },
      sandboxId: rec.sandboxId,
      harnessSession: thread.harnessSession,
      env: envFor(rec.sessionId, rec.def.id),
    });
    const reply: Message = { role: "assistant", text: out.text, ts: Date.now() };
    if (out.harnessSession) thread.harnessSession = out.harnessSession;
    thread.messages.push(reply);
    await saveThread(rec.sandboxId, thread);
    return { reply };
  } catch (e) {
    thread.messages.pop(); // don't persist a user turn that errored with no reply
    return { error: String((e as Error)?.message ?? e) };
  }
}

// The thread a view names: its workspace-level key when it has one (the same window in the next
// session is the same chat), else the session-local view id (a chat that dies with the session).
export const threadKeyOf = (view: View): string => view.specKey || view.id;

// The agent a view is a window onto — by roster definition id or runtime id, in the view's session.
export function agentForView(view: View): (AgentRecord & { runtimeId: string }) | undefined {
  if (!view.agentId) return undefined;
  return [...live.entries()].filter(([, r]) => r.sandboxId === view.sandboxId).map(([runtimeId, r]) => ({ ...r, runtimeId })).find((a) => a.def.id === view.agentId || a.runtimeId === view.agentId);
}

// A thread's transcript for the API.
export async function threadMessages(view: View): Promise<Message[]> {
  const rec = agentForView(view);
  if (!rec?.sandboxId) return [];
  return (await loadThread(rec.sandboxId, threadKeyOf(view), rec.def.id)).messages;
}

// JSON projections for the API.
export const agentJson = (r: AgentRecord & { runtimeId: string }) => ({
  id: r.runtimeId,
  defId: r.def.id,
  name: r.def.name,
  harness: r.def.harness,
  model: r.def.model ?? null,
  npub: r.def.npub ?? null,
  lifecycle: r.def.lifecycle ?? "always",
  status: r.status,
});

export { STORE as AGENTS_STORE };

// Parse the roster from a launch body (the web sends the workspace's agents inline).
export function parseRoster(raw: unknown): AgentDef[] {
  if (!Array.isArray(raw)) return [];
  const out: AgentDef[] = [];
  for (const a of raw) {
    // The cloud's compose-launch specs carry the agent id as `key` and the prompt as
    // `instructions` (PLAN §12); the daemon-era roster used `id` / `systemPrompt`. Take either.
    const id = typeof a?.id === "string" ? a.id : typeof a?.key === "string" ? a.key : undefined;
    if (!id || typeof a?.name !== "string") continue;
    out.push({
      id,
      name: a.name,
      harness: (typeof a.harness === "string" ? a.harness : "echo") as HarnessId,
      model: typeof a.model === "string" ? a.model : null,
      systemPrompt: typeof a.systemPrompt === "string" ? a.systemPrompt : typeof a.instructions === "string" ? a.instructions : "",
      npub: typeof a.npub === "string" ? a.npub : undefined,
      lifecycle: a.lifecycle === "lazy" ? "lazy" : "always",
    });
  }
  return out;
}

// Warm-load nothing on boot; conversations are lazy-read per agent. Exposed for tests.
export function _reset(): void {
  live.clear();
}
export function _persistedWorkspaces(): string[] {
  try {
    return readdirSync(STORE);
  } catch {
    return [];
  }
}
