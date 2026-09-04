// The ACP agent view's server side (PLAN §5d): materialize an agent into its sandbox (its HOME,
// its harness's files, its credential), write the in-sandbox bridge + the `isolation` MCP server,
// and start the bridge on the view's port. The doorman then proxies the page's WebSocket to the
// bridge; connectors (Slack, Buzz, another agent) reach the same thread through the bridge's
// POST /prompt. Nothing chat-shaped lives on this host: the harness keeps the conversation in the
// agent's HOME (under the workspace tree → R2), the thread file keeps the harness session id.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { agentForView, credentialFor, effectiveSystemPrompt, threadKeyOf, type Message } from "./agents.js";
import { downloadFile, run, writeFile } from "./execd.js";
import { getHarness, mcpEnvList } from "./harness.js";
import { endpointFor } from "./opensandbox.js";
import { agentHome, memoryPath, threadPath } from "./threads.js";
import { viewsForSandbox, type View } from "./views.js";

const log = (...a: unknown[]) => console.log("[acp]", ...a);

const SANDBOX_DIR = join(dirname(fileURLToPath(import.meta.url)), "sandbox");
const BRIDGE_SRC = readFileSync(join(SANDBOX_DIR, "iso-acp-bridge.mjs"), "utf8");
const MCP_SRC = readFileSync(join(SANDBOX_DIR, "iso-mcp.mjs"), "utf8");

export const BRIDGE_PATH = "/tmp/.iso-acp-bridge.mjs";
export const MCP_PATH = "/tmp/.iso-mcp.mjs";
export const MCP_WRAPPER = "/tmp/.iso-mcp.sh";
export const VIEWS_FILE = "/tmp/.iso-views.json";
const WORKSPACE = "/workspace";
// The bundled Node when the base image has none of its own (spec images ship `iso-node`).
const NODE = `$(command -v iso-node || command -v node)`;
const MCP_WRAPPER_SRC = `#!/bin/sh\nexec "$(command -v iso-node || command -v node)" ${MCP_PATH} "$@"\n`;

// The thread file's harness session id — read straight from the sandbox (the BRIDGE writes it,
// so a server-side cache would hand a stale id to the next bridge and lose the conversation).
async function harnessSessionOf(sandboxId: string, key: string): Promise<string | undefined> {
  try {
    const r = await downloadFile(sandboxId, threadPath(key));
    if (!r.ok) return undefined;
    const t = JSON.parse(await r.text()) as { harnessSession?: unknown };
    return typeof t.harnessSession === "string" && t.harnessSession ? t.harnessSession : undefined;
  } catch {
    return undefined;
  }
}

export const bridgePattern = (view: View): string => `iso-acp-bridge.mjs ${view.port} `;

// Materialize + start the bridge for an agent view. Idempotent: any bridge already on the port is
// stopped first (the SPA deletes and recreates views on spec changes; a stale bridge would win
// the bind and front the wrong agent).
export async function startAgentBridge(view: View): Promise<void> {
  const rec = agentForView(view);
  if (!rec) {
    log(`${view.id}: no agent bound (agentId ${view.agentId ?? "-"}) — bridge not started`);
    return;
  }
  const harness = getHarness(rec.def.harness);
  const home = agentHome(rec.def.id);
  const key = threadKeyOf(view);
  const credential = credentialFor(rec.sessionId, rec.def.id);
  const mcpEnv: Record<string, string> = {
    ISO_AGENT_ID: rec.def.id,
    ISO_AGENT_NAME: rec.def.name,
    ISO_HARNESS: rec.def.harness,
    ISO_SESSION_ID: rec.sessionId,
    ISO_WORKSPACE_ID: rec.workspaceId,
    ISO_VIEW_ID: view.id,
    ISO_MEMORY_PATH: memoryPath(rec.def.id),
    ISO_VIEWS_FILE: VIEWS_FILE,
  };
  let m;
  try {
    m = harness.materialize({ home, agent: { id: rec.def.id, name: rec.def.name, model: rec.def.model ?? undefined }, persona: effectiveSystemPrompt(rec.def), credential, mcp: { name: "isolation", command: MCP_WRAPPER, args: [], env: mcpEnv } });
  } catch (e) {
    log(`${view.id}: ${String((e as Error)?.message ?? e)}`);
    return;
  }
  const sessionId = await harnessSessionOf(view.sandboxId, key);
  const config = {
    viewId: view.id,
    threadKey: key,
    agent: { id: rec.def.id, name: rec.def.name, harness: rec.def.harness, model: rec.def.model ?? null },
    command: m.command,
    args: m.args,
    env: m.env,
    // The container env carries the SESSION's credential; an agent with its own must not
    // inherit the other half of the pair (harness.ts `unsetFor`).
    unsetEnv: m.unsetEnv ?? [],
    cwd: WORKSPACE,
    home,
    sessionId,
    statePath: threadPath(key),
    mcpServers: [{ name: "isolation", command: MCP_WRAPPER, args: [], env: mcpEnvList(mcpEnv) }],
    initialModeId: m.initialModeId,
    idleMinutes: 15,
  };
  const cfgPath = `/tmp/.iso-acp-${view.id}.json`;
  await writeFile(view.sandboxId, BRIDGE_PATH, BRIDGE_SRC, 0o644);
  await writeFile(view.sandboxId, MCP_PATH, MCP_SRC, 0o644);
  await writeFile(view.sandboxId, MCP_WRAPPER, MCP_WRAPPER_SRC, 0o755);
  // The agent's HOME is under the workspace tree so the conversation persists — and that tree is
  // committed and bundled to R2. Credential material must never ride it, so the HOME carries its
  // own .gitignore, written BEFORE the harness's files: git honours a nested .gitignore whether
  // or not it is tracked, and `git add -A`/`git clean -fd` both respect it.
  await writeFile(view.sandboxId, `${home}/.gitignore`, `${["# isolation: harness credential material — never persisted (secrets never in bundles/git)", ...(m.secretPaths ?? []).map((p) => `/${p.replace(/^\/+/, "")}`)].join("\n")}\n`, 0o600);
  for (const f of m.files) await writeFile(view.sandboxId, f.path, f.content, f.mode ?? 0o600);
  await writeFile(view.sandboxId, cfgPath, JSON.stringify(config), 0o600);
  await run(view.sandboxId, `mkdir -p ${JSON.stringify(home)} ${JSON.stringify(dirname(threadPath(key)))}; pkill -f ${JSON.stringify(bridgePattern(view))} || true`).catch(() => undefined);
  // execd's background mode owns the process's lifetime — no nohup/& wrappers.
  await run(view.sandboxId, `${NODE} ${BRIDGE_PATH} ${view.port} ${cfgPath}`, { cwd: WORKSPACE, background: true });
  log(`${view.id}: bridge on :${view.port} for "${rec.def.name}" (${rec.def.harness}${sessionId ? `, resuming ${sessionId.slice(0, 8)}` : ""})`);
}

export async function stopAgentBridge(view: View): Promise<void> {
  await run(view.sandboxId, `pkill -f ${JSON.stringify(bridgePattern(view))} || true`).catch(() => undefined);
}

// The bridge's own health endpoint, through execd's proxy — what the doorman checks before it
// upgrades a page's WebSocket (execd answers a dead port with a 502 RESPONSE, which the proxy
// relays silently; without this the page would retry forever against nothing).
// The port alone is NOT identity: view ports are recycled (nextFree only avoids LIVE views), so a
// bridge left behind by a deleted view can still hold this one's port. It answers /health quite
// happily — and proxying to it would front another agent's thread. Health means "the bridge for
// THIS view", so the answer must name the view; anything else is treated as dead and replaced.
export async function bridgeHealthy(view: View): Promise<boolean> {
  try {
    const ep = await endpointFor(view.sandboxId, view.port);
    const r = await fetch(`http://${ep.host}${ep.basePath}/health`, { signal: AbortSignal.timeout(3_000) });
    if (!r.ok) return false;
    const body = (await r.json().catch(() => ({}))) as { viewId?: unknown };
    return body.viewId === view.id;
  } catch {
    return false;
  }
}

// Make sure a bridge answers: restart it when it doesn't, and wait (briefly) for it to bind.
// ONE heal in flight per view (the doorman's reconnects and a connector turn can arrive
// together) — concurrent callers share the attempt instead of racing pkill/start against
// each other and killing the bridge the other just started.
const heals = new Map<string, Promise<boolean>>();
export function ensureBridge(view: View): Promise<boolean> {
  let p = heals.get(view.id);
  if (!p) {
    p = healBridge(view).finally(() => heals.delete(view.id));
    heals.set(view.id, p);
  }
  return p;
}

async function healBridge(view: View): Promise<boolean> {
  if (await bridgeHealthy(view)) return true;
  log(`${view.id}: bridge not answering — restarting`);
  await startAgentBridge(view);
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 500));
    if (await bridgeHealthy(view)) return true;
  }
  return false;
}

export async function bridgeAlive(view: View): Promise<boolean> {
  try {
    const r = await run(view.sandboxId, `pgrep -f ${JSON.stringify(bridgePattern(view))} >/dev/null && echo alive || echo dead`, { timeoutMs: 10_000 });
    return /alive/.test(r.stdout);
  } catch {
    return false;
  }
}

// The session's views, as the `isolation` MCP server lists them (and `thread_send` dials them).
export async function syncViewsFile(sandboxId: string): Promise<void> {
  const rows = viewsForSandbox(sandboxId).map((v) => {
    const a = v.type === "agent" ? agentForView(v) : undefined;
    return { id: v.id, type: v.type, label: v.label ?? null, port: v.port || null, specKey: v.specKey ?? null, ...(a ? { agentId: a.def.id, agentName: a.def.name, harness: a.def.harness } : {}) };
  });
  await writeFile(sandboxId, VIEWS_FILE, JSON.stringify(rows), 0o644).catch((e: Error) => log(`views file: ${e.message}`));
}

// A connector turn (Slack, Buzz, the control plane): one prompt through the bridge, the reply
// text back — the same shape the old per-turn runner returned, so the routes stay.
export async function connectorTurn(view: View, text: string, from = "control-plane"): Promise<{ reply: Message } | { error: string }> {
  if (!view.port) return { error: "this agent view has no bridge" };
  // Same pre-flight as the doorman's WebSocket upgrade: a bridge that was just scaffolded has
  // not necessarily bound yet, and one lost to a crash/restart would answer with execd's 502.
  // A connector turn has no page to retry for it, so heal (and wait) before prompting.
  if (!(await ensureBridge(view))) return { error: "the agent's bridge is not running" };
  let ep: { host: string; basePath: string };
  try {
    ep = await endpointFor(view.sandboxId, view.port);
  } catch (e) {
    return { error: `bridge unreachable: ${String((e as Error)?.message ?? e)}` };
  }
  try {
    const r = await fetch(`http://${ep.host}${ep.basePath}/prompt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, from }),
      signal: AbortSignal.timeout(20 * 60_000),
    });
    const body = (await r.json().catch(() => ({}))) as { text?: string; error?: string };
    if (!r.ok) return { error: body.error ?? `bridge → HTTP ${r.status}` };
    return { reply: { role: "assistant", text: body.text ?? "", ts: Date.now() } };
  } catch (e) {
    return { error: String((e as Error)?.message ?? e) };
  }
}
