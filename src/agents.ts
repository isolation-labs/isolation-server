// The agent supervisor (PLAN O5a — design in docs/O5-agents.md). A session runs N
// independent agents; each is its OWN conversation (a Claude-session-in-Cursor), with
// its own identity, harness, and memory. No shared room, no coordinator. Coordination +
// management is the control plane here (list/start/stop/message/spawn) — the operations
// the web sidebar drives and, later, the iso-mcp tools an external orchestrator calls.
//
// Memory is AGNOSTIC: each agent's conversation persists per (workspace, agent) behind a
// store interface (local per-server file now; the workspace persistence layer — R2 /
// workspace file / injected sink — is the multi-server backing, O5 follow-up). Stable per
// (workspace, agent) across sessions. Harness is pluggable + agnostic (echo built-in for
// credential-free runs; claude-code/codex/gemini adapters plug in the same interface).
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "./config.js";
import { getHarness, type HarnessId } from "./harness.js";

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
  conversation: Message[];
}

// Live agents, keyed by a session-scoped runtime id (`a-…`). The DEFINITION id is stable
// per workspace; the runtime id is this instance in this session.
const live = new Map<string, AgentRecord>();

// --- agnostic conversation memory (per workspace, per agent) -------------------

function convPath(workspaceId: string, agentDefId: string): string {
  const dir = join(STORE, safe(workspaceId));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return join(dir, `${safe(agentDefId)}.json`);
}
const safe = (s: string): string => s.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 128) || "x";

function loadConversation(workspaceId: string, agentDefId: string): Message[] {
  try {
    return JSON.parse(readFileSync(convPath(workspaceId, agentDefId), "utf8")) as Message[];
  } catch {
    return [];
  }
}
function saveConversation(rec: AgentRecord): void {
  const p = convPath(rec.workspaceId, rec.def.id);
  const tmp = `${p}.tmp`;
  writeFileSync(tmp, JSON.stringify(rec.conversation), { mode: 0o600 });
  renameSync(tmp, p);
}

// --- the base Isolation system prompt (framework layer) ------------------------

// Prepended to every agent's user prompt, per-harness. Teaches the environment: the
// workspace, the tools, the collaboration model. Kept short + agnostic; a real harness
// adapter renders it into that harness's system-prompt slot.
function basePrompt(def: AgentDef): string {
  return [
    `You are "${def.name}", an autonomous agent working inside an Isolation session — an isolated container with a project checked out at /workspace.`,
    `You are one of several independent agents on this workspace; each has its own separate conversation. You do NOT share a chat with the others.`,
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
    conversation: loadConversation(workspaceId, def.id), // re-hydrate stable memory
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
export function spawnAgent(sessionId: string, def: AgentDef): (AgentRecord & { runtimeId: string }) | { error: string } {
  const any = [...live.values()].find((r) => r.sessionId === sessionId);
  if (!any) return { error: "unknown or not-ready session" };
  const rec = newAgent(any.workspaceId, sessionId, any.sandboxId, def, "running") as AgentRecord & { runtimeId: string };
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
}

// --- the conversation turn ------------------------------------------------------

// Send a message to ONE agent and get its reply. Boots a lazy/stopped agent (a message is
// an implicit start). Persists the thread (agnostic memory). Independent per agent.
export async function sendMessage(agentId: string, text: string, from = "sidebar"): Promise<{ reply: Message } | { error: string }> {
  const id = findRuntimeId(agentId);
  if (!id) return { error: "unknown agent" };
  const rec = live.get(id) as AgentRecord;
  if (rec.status !== "running") rec.status = "running"; // a message starts a lazy/stopped agent
  const user: Message = { role: "user", text, ts: Date.now(), from };
  rec.conversation.push(user);
  try {
    const harness = getHarness(rec.def.harness);
    const replyText = await harness.runTurn({
      systemPrompt: effectiveSystemPrompt(rec.def),
      history: rec.conversation.slice(0, -1),
      userText: text,
      agent: { id: rec.def.id, name: rec.def.name, model: rec.def.model ?? undefined },
      sandboxId: rec.sandboxId,
    });
    const reply: Message = { role: "assistant", text: replyText, ts: Date.now() };
    rec.conversation.push(reply);
    saveConversation(rec);
    return { reply };
  } catch (e) {
    rec.conversation.pop(); // don't persist a user turn that errored with no reply
    return { error: String((e as Error)?.message ?? e) };
  }
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
  messages: r.conversation.length,
});

export { STORE as AGENTS_STORE };

// Parse the roster from a launch body (the web sends the workspace's agents inline).
export function parseRoster(raw: unknown): AgentDef[] {
  if (!Array.isArray(raw)) return [];
  const out: AgentDef[] = [];
  for (const a of raw) {
    if (typeof a?.id !== "string" || typeof a?.name !== "string") continue;
    out.push({
      id: a.id,
      name: a.name,
      harness: (typeof a.harness === "string" ? a.harness : "echo") as HarnessId,
      model: typeof a.model === "string" ? a.model : null,
      systemPrompt: typeof a.systemPrompt === "string" ? a.systemPrompt : "",
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
