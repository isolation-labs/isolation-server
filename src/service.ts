// OS service install — `isogate up` installs/refreshes the gate as the user's
// login service and starts it; `isogate down` stops and disables it. Same
// service-only model as the isolation CLI (no PID-file mode): dev/CI runs
// `node dist/index.js` directly. macOS launchd now; systemd --user next.
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { HOME } from "./config.js";

const LABEL = "cc.isolation.isogate";

const plistPath = (): string => join(homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);

// The daemon entry next to this compiled file — the service always runs the build
// it was installed from.
const entryPath = (): string => join(fileURLToPath(new URL(".", import.meta.url)), "index.js");

function launchctl(...args: string[]): void {
  execFileSync("launchctl", args, { stdio: "ignore" });
}

export function serviceUp(): void {
  if (process.platform !== "darwin") {
    throw new Error("service install currently supports macOS (launchd) only — run `node dist/index.js` directly");
  }
  mkdirSync(join(homedir(), "Library", "LaunchAgents"), { recursive: true });
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  const node = process.execPath;
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>${node}</string>
    <string>${entryPath()}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${join(HOME, "isogate.log")}</string>
  <key>StandardErrorPath</key><string>${join(HOME, "isogate.log")}</string>
</dict></plist>
`;
  writeFileSync(plistPath(), plist);
  // Refresh semantics: bootout (ignore "not loaded"), then bootstrap the new plist.
  try {
    launchctl("bootout", `gui/${process.getuid?.() ?? 501}`, plistPath());
  } catch {
    /* not loaded — fine */
  }
  launchctl("bootstrap", `gui/${process.getuid?.() ?? 501}`, plistPath());
}

export function serviceDown(): void {
  if (process.platform !== "darwin") throw new Error("service management currently supports macOS only");
  try {
    launchctl("bootout", `gui/${process.getuid?.() ?? 501}`, plistPath());
  } catch {
    /* already stopped */
  }
}
