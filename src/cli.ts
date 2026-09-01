#!/usr/bin/env node
// isolation-server CLI — MVP surface: run the gate, link it to an account, inspect it.
//   isolation-server up                  install + start as the OS login service (refreshes on re-run)
//   isolation-server down                stop + disable the service
//   isolation-server run                 run the gate in the foreground (dev / supervisor-less)
//   isolation-server connect <code>      link this server to the cloud account that minted the code
//   isolation-server disconnect          unlink (detach pairing + drop the tunnel)
//   isolation-server status              show gate / runtime / tunnel / pairing state
//
// What `connect` takes is the SHORT code the web shows — six unambiguous characters a human
// reads off a screen and types ("isolation connect UDWYUV"). It pairs against the production
// backend; any other deployment (staging, a self-host, a dev worker) names itself in the open
// with `--backend <url>`, which is a flag someone can see and reason about. The old
// self-describing token — base64url({u: <backend origin>, c: <code>}) — still resolves, so
// codes copied from an older web build keep working.
import { HOST, PORT, getToken } from "./config.js";
import { gateArgv, installService, uninstallService } from "./service.js";
import { prepareRuntime, waitForRuntime } from "./runtime.js";
import { ensureCloudflared } from "./cloudflared.js";

const base = `http://${HOST}:${PORT}`;

// Where a BARE pairing code pairs against. The one SaaS URL the CLI knows, and only as the
// default for the short-code path — every other deployment passes --backend.
const DEFAULT_BACKEND = "https://app.isolation.cloud";

/** The legacy self-describing token: base64url({u,c}). null when the argument isn't one. */
function decodePairToken(arg: string): { u: string; c: string } | null {
  try {
    const d = JSON.parse(Buffer.from(arg, "base64url").toString("utf8")) as { u?: string; c?: string };
    return typeof d?.u === "string" && typeof d?.c === "string" ? { u: d.u, c: d.c } : null;
  } catch {
    return null;
  }
}
const authed = (init?: RequestInit): RequestInit => ({
  ...init,
  headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json", ...(init?.headers ?? {}) },
});

async function main(): Promise<void> {
  const [cmd, arg, ...rest] = process.argv.slice(2);

  if (cmd === "run") {
    await import("./index.js");
    return;
  }

  if (cmd === "up") {
    const say = (m: string) => console.log(`  ${m}`);
    // 1. The runtime: pinned opensandbox-server via uv, loopback config with a minted
    //    API key, as a service — unless one is already running (adopted as-is).
    const rt = await prepareRuntime(say);
    if (!rt.alreadyRunning) {
      installService({ id: "runtime", argv: [rt.serverBin] });
      if (!(await waitForRuntime())) return fail("opensandbox-server didn't become healthy — is Docker running? see ~/.isolation-server/opensandbox.log");
      say(`opensandbox-server ${rt.port ? `on :${rt.port}` : ""} up (login service)`);
    }
    // 2. The relay binary, pre-fetched so `connect` never waits on a download.
    await ensureCloudflared(say).catch((e: Error) => say(`(cloudflared not provisioned yet: ${e.message})`));
    // 3. The gate itself.
    installService({ id: "gate", argv: gateArgv() });
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const r = await fetch(`${base}/status`, authed()).catch(() => undefined);
      if (r?.ok) {
        console.log(`isolation-server is up on ${base} (login service)`);
        return;
      }
    }
    return fail("service installed but the gate didn't come up — check ~/.isolation-server/isolation-server.log");
  }

  if (cmd === "down") {
    uninstallService("gate");
    uninstallService("runtime");
    console.log("isolation-server + runtime services stopped");
    return;
  }

  if (cmd === "connect") {
    if (!arg) fail("usage: isolation-server connect <code> [--backend <url>]");
    const flag = rest.indexOf("--backend");
    if (flag >= 0 && !rest[flag + 1]) return fail("--backend needs a URL, e.g. --backend https://staging.isolation.cloud");
    const override = flag >= 0 ? rest[flag + 1] : undefined;
    if (override && !/^https?:\/\//.test(override)) return fail(`--backend must be an http(s) URL, got "${override}"`);

    // A legacy token carries its own origin; a bare code is the common case and pairs against
    // production unless --backend says otherwise. An explicit flag always wins.
    const token = decodePairToken(arg);
    const code = (token?.c ?? arg).trim().toUpperCase();
    const backendUrl = override ?? token?.u ?? DEFAULT_BACKEND;
    if (!token && !/^[A-Z0-9]{4,16}$/.test(code)) return fail(`"${arg}" is not a pairing code — copy the one the web app shows`);

    const r = await fetch(`${base}/pair`, authed({ method: "POST", body: JSON.stringify({ backendUrl, code }) })).catch(() => undefined);
    if (!r) return fail(`the gate isn't running on ${base} — start it with: isolation-server run`);
    const body = (await r.json().catch(() => ({}))) as { ok?: boolean; label?: string; url?: string; error?: string };
    if (!r.ok || !body.ok) return fail(body.error ?? `pairing failed (HTTP ${r.status})`);
    console.log(`paired as "${body.label}" — reachable at ${body.url}`);
    return;
  }

  if (cmd === "disconnect") {
    const r = await fetch(`${base}/pair`, authed({ method: "DELETE" })).catch(() => undefined);
    if (!r) return fail(`the gate isn't running on ${base}`);
    console.log("disconnected");
    return;
  }

  if (cmd === "update") {
  // Update = reinstall from npm + refresh the service to the new build. The service
  // runs the build it was installed from, so `up` must follow the install.
  const { execFileSync } = await import("node:child_process");
  console.log("updating isolation-server from npm…");
  execFileSync("npm", ["install", "-g", "isolation-server@latest"], { stdio: "inherit" });
  const pkgRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
  execFileSync(process.execPath, [`${pkgRoot}/isolation-server/dist/cli.js`, "up"], { stdio: "inherit" });
  process.exit(0);
}

if (cmd === "status") {
    const r = await fetch(`${base}/status`, authed()).catch(() => undefined);
    if (!r) return fail(`the gate isn't running on ${base} — start it with: isolation-server run`);
    console.log(JSON.stringify(await r.json(), null, 2));
    return;
  }

  console.log("usage: isolation-server <up|down|run|connect <code> [--backend <url>]|disconnect|status>");
}

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

void main();
