// The OpenSandbox runtime, owned by the gate: `isolation-server up` makes sure a PINNED
// `opensandbox-server` is installed (via uv, no root), configured for the Docker
// runtime on loopback with an API key the gate minted, and running as a service
// next to the gate. Users never touch OpenSandbox directly — one command stands
// the whole server up. An already-running runtime (e.g. started by hand) is
// adopted, not fought over.
import { randomBytes } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { getOsb, saveOsb } from "./config.js";
import { osbHealthy } from "./opensandbox.js";

export const OPENSANDBOX_VERSION = "0.2.3";
export const SANDBOX_TOML = process.env.ISOLATION_SERVER_SANDBOX_TOML ?? join(homedir(), ".sandbox.toml");

const candidates = (name: string): string[] => [
  join(homedir(), ".local", "bin", name),
  `/opt/homebrew/bin/${name}`,
  `/usr/local/bin/${name}`,
  name, // PATH
];
const runnable = (bin: string): boolean => !spawnSync(bin, ["--version"], { stdio: "ignore" }).error;
const find = (name: string): string | undefined => candidates(name).find(runnable);

// uv is the installer for the Python-packaged server: a single-binary, user-local
// install with no system Python dependency.
function ensureUv(log: (m: string) => void): string {
  const uv = find("uv");
  if (uv) return uv;
  log("installing uv (user-local)…");
  const r = spawnSync("sh", ["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"], { stdio: "ignore", env: { ...process.env, UV_NO_MODIFY_PATH: "1" } });
  const after = find("uv");
  if (r.status !== 0 || !after) throw new Error("could not install uv — install it from https://docs.astral.sh/uv/ and re-run `isolation-server up`");
  return after;
}

export function ensureServerInstalled(log: (m: string) => void): string {
  const uv = ensureUv(log);
  const bin = find("opensandbox-server");
  // The server has no --version flag; uv's tool registry is the source of truth
  // ("opensandbox-server v0.2.3"). Reinstall only when the pin isn't what's installed.
  const listed = spawnSync(uv, ["tool", "list"], { encoding: "utf8" }).stdout ?? "";
  const current = /opensandbox-server v(\S+)/.exec(listed)?.[1] ?? "";
  if (!bin || current !== OPENSANDBOX_VERSION) {
    log(`installing opensandbox-server ${OPENSANDBOX_VERSION}…`);
    execFileSync(uv, ["tool", "install", "--force", `opensandbox-server==${OPENSANDBOX_VERSION}`], { stdio: "ignore" });
  }
  const installed = find("opensandbox-server");
  if (!installed) throw new Error("opensandbox-server not runnable after install (is ~/.local/bin on PATH?)");
  return installed;
}

// Config: generate the docker example if none exists, then make sure it binds
// loopback and carries an API key. An existing file is respected — we only fill a
// missing/empty key (never rotate one the runtime is already using).
export function ensureServerConfig(serverBin: string, log: (m: string) => void): { apiKey: string; port: number } {
  if (!existsSync(SANDBOX_TOML)) {
    log(`writing ${SANDBOX_TOML} (docker runtime)…`);
    execFileSync(serverBin, ["init-config", SANDBOX_TOML, "--example", "docker"], { stdio: "ignore" });
  }
  let toml = readFileSync(SANDBOX_TOML, "utf8");
  let apiKey = /^\s*api_key\s*=\s*"([^"]*)"/m.exec(toml)?.[1] ?? "";
  if (!apiKey) {
    apiKey = randomBytes(32).toString("hex");
    toml = /^\s*#?\s*api_key\s*=.*$/m.test(toml)
      ? toml.replace(/^\s*#?\s*api_key\s*=.*$/m, `api_key = "${apiKey}"`)
      : toml.replace(/^\[server\]\s*$/m, `[server]\napi_key = "${apiKey}"`);
    writeFileSync(SANDBOX_TOML, toml, { mode: 0o600 });
    log("minted the runtime API key");
  }
  const port = Number(/^\s*port\s*=\s*(\d+)/m.exec(toml)?.[1] ?? 8080);
  saveOsb({ url: `http://127.0.0.1:${port}`, apiKey });
  return { apiKey, port };
}

export interface RuntimePlan {
  serverBin: string;
  port: number;
  alreadyRunning: boolean; // an unmanaged instance answers /health → adopt it
}

export async function prepareRuntime(log: (m: string) => void): Promise<RuntimePlan> {
  const serverBin = ensureServerInstalled(log);
  const { port } = ensureServerConfig(serverBin, log);
  const alreadyRunning = await osbHealthy();
  if (alreadyRunning) log(`runtime already running on ${getOsb().url} — adopting it (not managed by the gate)`);
  return { serverBin, port, alreadyRunning };
}

export async function waitForRuntime(timeoutMs = 60_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await osbHealthy()) return true;
    await new Promise((r) => setTimeout(r, 1_000));
  }
  return false;
}
