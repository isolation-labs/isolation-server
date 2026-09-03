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
  harnessSession?: string; // the harness's own resumable session id (claude-code --resume, goose session)
  createdAt: number;
  updatedAt: number;
}

const safeKey = (k: string): string => k.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 120) || "thread";
const threadPath = (key: string) => `${THREADS_DIR}/${safeKey(key)}.json`;

// Per-sandbox cache: the sandbox is the truth, this only spares a download per turn. Dropped
// with the sandbox (forgetThreads) — a resumed session re-reads from the tree.
const cache = new Map<string, Thread>();
const cacheKey = (sandboxId: string, key: string) => `${sandboxId}:${safeKey(key)}`;

export async function loadThread(sandboxId: string, key: string, agentId: string): Promise<Thread> {
  const hit = cache.get(cacheKey(sandboxId, key));
  if (hit) return hit;
  let t: Thread | undefined;
  try {
    const r = await downloadFile(sandboxId, threadPath(key));
    if (r.ok) {
      const parsed = JSON.parse(await r.text()) as Partial<Thread>;
      if (Array.isArray(parsed.messages)) {
        t = { key: safeKey(key), agentId: parsed.agentId ?? agentId, messages: parsed.messages as Message[], harnessSession: parsed.harnessSession, createdAt: parsed.createdAt ?? Date.now(), updatedAt: parsed.updatedAt ?? Date.now() };
      }
    }
  } catch {
    /* no thread yet, or the sandbox isn't reachable — start empty */
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
    const r = await downloadFile(sandboxId, `${AGENTS_DIR}/${safeKey(agentId)}/memory.md`);
    return r.ok ? (await r.text()).slice(0, 16_000) : "";
  } catch {
    return "";
  }
}
