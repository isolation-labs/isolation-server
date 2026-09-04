// Threads (PLAN §12 v3, 2026-09-03): A VIEW IS THE THREAD. An agent view is one conversation with
// one agent; its stable key (the workspace-level view id — `specKey` — so the same window in the
// next session is the same chat) names the thread. The transcript lives INSIDE the sandbox, under
// the workspace tree, so it rides workspace persistence to R2 like any file and survives any
// server: `/workspace/.isolation/threads/<key>.json`. Nothing about a chat is kept on this host.
//
// A thread is reachable only while a session of its workspace runs — agents run inside sessions,
// by design. Channels (Slack, Buzz) are agent views too, just not placed in a layout; they route
// to the same store through the same key.
//
// MEMORY is separate from threads: one per-agent, per-workspace note the agent keeps for itself
// (`/workspace/.isolation/agents/<agentId>/memory.md`), read at the start of every turn.
import { downloadFile, writeFile } from "./execd.js";
import type { Message } from "./agents.js";

const THREADS_DIR = "/workspace/.isolation/threads";
const AGENTS_DIR = "/workspace/.isolation/agents";
const MAX_MESSAGES = 2000;

export interface Thread {
  key: string;
  agentId: string; // the roster DEFINITION id this thread talks to
  messages: Message[];
  harnessSession?: string; // the harness's ACP session id (PLAN §5d) — what the bridge reloads
  harness?: string;
  createdAt: number;
  updatedAt: number;
}

const safeKey = (k: string): string => k.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 120) || "thread";
export const threadPath = (key: string): string => `${THREADS_DIR}/${safeKey(key)}.json`;
export const memoryPath = (agentId: string): string => `${AGENTS_DIR}/${safeKey(agentId)}/memory.md`;
// The agent's own HOME (PLAN §5d): its harness's session store, instructions and credential
// files live here — under the workspace tree, so the conversation rides persistence to R2.
export const agentHome = (agentId: string): string => `${AGENTS_DIR}/${safeKey(agentId)}/home`;

// Per-sandbox cache: the sandbox is the truth, this only spares a download per turn. Dropped
// with the sandbox (forgetThreads) — a resumed session re-reads from the tree.
const cache = new Map<string, Thread>();
const cacheKey = (sandboxId: string, key: string) => `${sandboxId}:${safeKey(key)}`;

export async function loadThread(sandboxId: string, key: string, agentId: string): Promise<Thread> {
  const hit = cache.get(cacheKey(sandboxId, key));
  if (hit) return hit;
  // A transport failure is NOT "no thread yet": starting empty here would cache the empty
  // thread and have the next save overwrite a real transcript with a single turn. Only a
  // reachable sandbox that has no (or an unreadable) thread file starts one.
  let r: Response;
  try {
    r = await downloadFile(sandboxId, threadPath(key));
  } catch (e) {
    throw new Error(`thread ${safeKey(key)}: sandbox unreachable — ${String((e as Error)?.message ?? e)}`);
  }
  let t: Thread | undefined;
  if (r.ok) {
    try {
      const parsed = JSON.parse(await r.text()) as Partial<Thread>;
      if (Array.isArray(parsed.messages)) {
        t = { key: safeKey(key), agentId: parsed.agentId ?? agentId, messages: parsed.messages as Message[], harnessSession: parsed.harnessSession, harness: parsed.harness, createdAt: parsed.createdAt ?? Date.now(), updatedAt: parsed.updatedAt ?? Date.now() };
      }
    } catch {
      /* unreadable transcript — start a fresh one rather than wedging the chat */
    }
  } else {
    // Only "the file isn't there" (execd's 404) means "no thread yet". ANY other status is a
    // transport/server failure — starting empty on a 5xx would cache an empty thread and have
    // the next save overwrite the real transcript with a single turn.
    const body = await r.text().catch(() => "");
    if (r.status !== 404) throw new Error(`thread ${safeKey(key)}: read failed (HTTP ${r.status}) ${body.slice(0, 200)}`.trim());
  }
  if (!t) t = { key: safeKey(key), agentId, messages: [], createdAt: Date.now(), updatedAt: Date.now() };
  cache.set(cacheKey(sandboxId, key), t);
  return t;
}

export async function saveThread(sandboxId: string, t: Thread): Promise<void> {
  if (t.messages.length > MAX_MESSAGES) t.messages = t.messages.slice(-MAX_MESSAGES);
  t.updatedAt = Date.now();
  cache.set(cacheKey(sandboxId, t.key), t);
  await writeFile(sandboxId, threadPath(t.key), JSON.stringify(t), 0o600);
}

export const forgetThreads = (sandboxId: string): void => {
  for (const k of [...cache.keys()]) if (k.startsWith(`${sandboxId}:`)) cache.delete(k);
};

// The agent's own memory note (may not exist). Small by contract — it is prepended to the prompt.
export async function loadMemory(sandboxId: string, agentId: string): Promise<string> {
  try {
    const r = await downloadFile(sandboxId, memoryPath(agentId));
    return r.ok ? (await r.text()).slice(0, 16_000) : "";
  } catch {
    return "";
  }
}
