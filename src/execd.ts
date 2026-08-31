// Client for execd — the exec/file daemon OpenSandbox injects into every sandbox.
// isolation-server reaches it on the sandbox's published host port (endpoints API, port
// 44772) and uses it for everything that happens INSIDE a sandbox: view processes,
// clones, secret-file materialization, and (later) the persistence choreography.
import { endpointFor } from "./opensandbox.js";

const EXECD_PORT = 44772;

// Published host ports are stable while the sandbox runs; re-resolve on failure.
const hosts = new Map<string, string>();

async function execdHost(sandboxId: string): Promise<string> {
  const hit = hosts.get(sandboxId);
  if (hit) return hit;
  const ep = await endpointFor(sandboxId, EXECD_PORT);
  hosts.set(sandboxId, ep.host);
  return ep.host;
}

export const forgetExecd = (sandboxId: string): void => void hosts.delete(sandboxId);

export interface RunResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

interface RunOpts {
  cwd?: string;
  envs?: Record<string, string>;
  timeoutMs?: number;
  background?: boolean;
}

// Run a shell command. Foreground: parse execd's line-JSON stream into collected
// stdout/stderr (+ exit verdict). Background: fire and return immediately.
export async function run(sandboxId: string, command: string, opts: RunOpts = {}): Promise<RunResult> {
  const host = await execdHost(sandboxId);
  const r = await fetch(`http://${host}/command`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
      ...(opts.envs ? { envs: opts.envs } : {}),
      ...(opts.background ? { background: true } : {}),
      timeout: opts.timeoutMs ?? 120_000,
    }),
  });
  if (!r.ok) {
    hosts.delete(sandboxId);
    throw new Error(`execd /command → HTTP ${r.status}`);
  }
  const text = await r.text();
  let stdout = "";
  let stderr = "";
  let sawError = false;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const ev = JSON.parse(t) as { type?: string; text?: string };
      if (ev.type === "stdout") stdout += `${ev.text ?? ""}\n`;
      else if (ev.type === "stderr") stderr += `${ev.text ?? ""}\n`;
      else if (ev.type === "error") sawError = true;
    } catch {
      /* non-JSON noise — ignore */
    }
  }
  return { ok: !sawError, stdout, stderr };
}

// Write a file inside the sandbox (multipart upload; parent dirs created by execd).
export async function writeFile(sandboxId: string, path: string, content: string | Buffer, mode = 0o600): Promise<void> {
  const host = await execdHost(sandboxId);
  const form = new FormData();
  // execd quirks: metadata must be a FILE part, and mode a JSON NUMBER whose
  // decimal digits are read as octal (their docs' `mode: 755` convention).
  form.set("metadata", new Blob([JSON.stringify({ path, mode: Number(mode.toString(8)) })], { type: "application/json" }), "metadata.json");
  const bytes = typeof content === "string" ? Buffer.from(content, "utf8") : content;
  form.set("file", new Blob([new Uint8Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) as Uint8Array<ArrayBuffer>]));
  const r = await fetch(`http://${host}/files/upload`, { method: "POST", body: form });
  if (!r.ok) throw new Error(`execd upload ${path} → HTTP ${r.status}: ${(await r.text().catch(() => "")).slice(0, 200)}`);
}

// Wait until execd answers /ping — a fresh sandbox needs a moment before its
// injected daemon serves.
export async function waitReady(sandboxId: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "";
  while (Date.now() < deadline) {
    try {
      const host = await execdHost(sandboxId);
      const r = await fetch(`http://${host}/ping`, { signal: AbortSignal.timeout(2_000) });
      if (r.ok) return;
      lastErr = `HTTP ${r.status}`;
    } catch (e) {
      lastErr = String((e as Error)?.message ?? e);
      hosts.delete(sandboxId);
    }
    await new Promise((r) => setTimeout(r, 750));
  }
  throw new Error(`execd not ready after ${timeoutMs / 1000}s (${lastErr})`);
}
