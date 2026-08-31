#!/usr/bin/env node
// isolation-server CLI — MVP surface: run the gate, link it to an account, inspect it.
//   isolation-server up                  install + start as the OS login service (refreshes on re-run)
//   isolation-server down                stop + disable the service
//   isolation-server run                 run the gate in the foreground (dev / supervisor-less)
//   isolation-server connect <token>     link this server to the cloud account that minted the token
//   isolation-server disconnect          unlink (detach pairing + drop the tunnel)
//   isolation-server status              show gate / runtime / tunnel / pairing state
// The pair token is self-describing — base64url({u: <backend origin>, c: <code>}) —
// so the CLI never hardcodes a SaaS URL.
import { HOST, PORT, getToken } from "./config.js";
import { gateArgv, installService, uninstallService } from "./service.js";
import { prepareRuntime, waitForRuntime } from "./runtime.js";
import { ensureCloudflared } from "./cloudflared.js";

const base = `http://${HOST}:${PORT}`;
const authed = (init?: RequestInit): RequestInit => ({
  ...init,
  headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json", ...(init?.headers ?? {}) },
});

async function main(): Promise<void> {
  const [cmd, arg] = process.argv.slice(2);

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
    if (!arg) fail("usage: isolation-server connect <token>");
    let decoded: { u?: string; c?: string };
    try {
      decoded = JSON.parse(Buffer.from(arg, "base64url").toString("utf8")) as { u?: string; c?: string };
    } catch {
      return fail("invalid token (not a pair token)");
    }
    if (!decoded.u || !decoded.c) return fail("invalid token (missing fields)");
    const r = await fetch(`${base}/pair`, authed({ method: "POST", body: JSON.stringify({ backendUrl: decoded.u, code: decoded.c }) })).catch(() => undefined);
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

  if (cmd === "status") {
    const r = await fetch(`${base}/status`, authed()).catch(() => undefined);
    if (!r) return fail(`the gate isn't running on ${base} — start it with: isolation-server run`);
    console.log(JSON.stringify(await r.json(), null, 2));
    return;
  }

  console.log("usage: isolation-server <up|down|run|connect <token>|disconnect|status>");
}

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

void main();
