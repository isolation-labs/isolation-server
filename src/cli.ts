#!/usr/bin/env node
// isogate CLI — MVP surface: run the gate, link it to an account, inspect it.
//   isogate run                 run the gate in the foreground (service mgmt comes later)
//   isogate connect <token>     link this server to the cloud account that minted the token
//   isogate disconnect          unlink (detach pairing + drop the tunnel)
//   isogate status              show gate / runtime / tunnel / pairing state
// The pair token is self-describing — base64url({u: <backend origin>, c: <code>}) —
// so the CLI never hardcodes a SaaS URL.
import { HOST, PORT, getToken } from "./config.js";

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

  if (cmd === "connect") {
    if (!arg) fail("usage: isogate connect <token>");
    let decoded: { u?: string; c?: string };
    try {
      decoded = JSON.parse(Buffer.from(arg, "base64url").toString("utf8")) as { u?: string; c?: string };
    } catch {
      return fail("invalid token (not a pair token)");
    }
    if (!decoded.u || !decoded.c) return fail("invalid token (missing fields)");
    const r = await fetch(`${base}/pair`, authed({ method: "POST", body: JSON.stringify({ backendUrl: decoded.u, code: decoded.c }) })).catch(() => undefined);
    if (!r) return fail(`the gate isn't running on ${base} — start it with: isogate run`);
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
    if (!r) return fail(`the gate isn't running on ${base} — start it with: isogate run`);
    console.log(JSON.stringify(await r.json(), null, 2));
    return;
  }

  console.log("usage: isogate <run|connect <token>|disconnect|status>");
}

function fail(msg: string): never {
  console.error(msg);
  process.exit(1);
}

void main();
