// OS services — `isogate up` installs/refreshes the gate AND (unless adopted) the
// OpenSandbox runtime as the user's login services and starts them; `isogate down`
// stops + disables them. Service-only model (no PID-file mode): dev/CI runs
// `node dist/index.js` directly. macOS = launchd user agents; Linux = systemd --user.
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { HOME } from "./config.js";

export interface ServiceSpec {
  id: "gate" | "runtime";
  argv: string[];
  env?: Record<string, string>;
}

const LABELS: Record<ServiceSpec["id"], string> = { gate: "cc.isolation.isogate", runtime: "cc.isolation.opensandbox" };
const uid = (): number => process.getuid?.() ?? 501;

// The compiled gate entry next to this file — the service runs the build it was installed from.
export const gateArgv = (): string[] => [process.execPath, join(fileURLToPath(new URL(".", import.meta.url)), "index.js")];

export function installService(spec: ServiceSpec): void {
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  if (process.platform === "darwin") return launchdInstall(spec);
  if (process.platform === "linux") return systemdInstall(spec);
  throw new Error(`service install is not supported on ${process.platform} — run \`node dist/index.js\` directly`);
}

export function uninstallService(id: ServiceSpec["id"]): void {
  if (process.platform === "darwin") return launchdRemove(id);
  if (process.platform === "linux") return systemdRemove(id);
}

// --- launchd ------------------------------------------------------------------

const plistPath = (id: ServiceSpec["id"]): string => join(homedir(), "Library", "LaunchAgents", `${LABELS[id]}.plist`);
const launchctl = (...args: string[]): void => void execFileSync("launchctl", args, { stdio: "ignore" });
const xml = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

function launchdInstall(spec: ServiceSpec): void {
  mkdirSync(join(homedir(), "Library", "LaunchAgents"), { recursive: true });
  const log = join(HOME, `${spec.id === "gate" ? "isogate" : "opensandbox"}.log`);
  const env = { PATH: `${join(homedir(), ".local", "bin")}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`, HOME: homedir(), ...(spec.env ?? {}) };
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABELS[spec.id]}</string>
  <key>ProgramArguments</key><array>${spec.argv.map((a) => `<string>${xml(a)}</string>`).join("")}</array>
  <key>EnvironmentVariables</key><dict>${Object.entries(env)
    .map(([k, v]) => `<key>${xml(k)}</key><string>${xml(v)}</string>`)
    .join("")}</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict></plist>
`;
  writeFileSync(plistPath(spec.id), plist);
  try {
    launchctl("bootout", `gui/${uid()}`, plistPath(spec.id)); // refresh: drop the old definition first
  } catch {
    /* not loaded */
  }
  launchctl("bootstrap", `gui/${uid()}`, plistPath(spec.id));
}

function launchdRemove(id: ServiceSpec["id"]): void {
  try {
    launchctl("bootout", `gui/${uid()}`, plistPath(id));
  } catch {
    /* already stopped */
  }
  rmSync(plistPath(id), { force: true });
}

// --- systemd --user ------------------------------------------------------------

const unitDir = (): string => join(homedir(), ".config", "systemd", "user");
const unitName = (id: ServiceSpec["id"]): string => `${LABELS[id]}.service`;
const systemctl = (...args: string[]): void => void execFileSync("systemctl", ["--user", ...args], { stdio: "ignore" });

function systemdInstall(spec: ServiceSpec): void {
  mkdirSync(unitDir(), { recursive: true });
  const env = { PATH: `${join(homedir(), ".local", "bin")}:/usr/local/bin:/usr/bin:/bin`, ...(spec.env ?? {}) };
  const unit = `[Unit]
Description=${spec.id === "gate" ? "isogate — the Isolation gate" : "OpenSandbox runtime (managed by isogate)"}
After=network-online.target docker.service

[Service]
ExecStart=${spec.argv.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}
${Object.entries(env)
  .map(([k, v]) => `Environment=${k}=${v}`)
  .join("\n")}
Restart=always
RestartSec=3
StandardOutput=append:${join(HOME, `${spec.id === "gate" ? "isogate" : "opensandbox"}.log`)}
StandardError=inherit

[Install]
WantedBy=default.target
`;
  writeFileSync(join(unitDir(), unitName(spec.id)), unit);
  systemctl("daemon-reload");
  systemctl("enable", "--now", unitName(spec.id));
  systemctl("restart", unitName(spec.id)); // refresh semantics: pick up a new build/config
}

function systemdRemove(id: ServiceSpec["id"]): void {
  try {
    systemctl("disable", "--now", unitName(id));
  } catch {
    /* not installed */
  }
  rmSync(join(unitDir(), unitName(id)), { force: true });
  try {
    systemctl("daemon-reload");
  } catch {
    /* ignore */
  }
}
