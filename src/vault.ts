// The Credential Vault (PLAN §5b) — the ONE way a sandbox gets credentials. Nothing secret
// is ever placed in the container: the runtime's egress sidecar (transparent HTTPS MITM)
// holds the values in its own memory and injects the right header on the way out, per
// host/path binding. Tools inside run with fake/empty keys and never notice.
//
// What arrives here is a MANIFEST (sealed to this server, like every launch secret): the
// credentials (name → value) and the bindings (host/path → which credential, as which
// header). For `gateway`-delivered credentials the value is a scoped `isogw_` token and the
// host is the SaaS gateway that swaps it for the real one; for `direct` ones the value is
// the real token and the host is the upstream itself. This module doesn't care which —
// that decision was made where the manifest was minted.
//
// Lifetime = the sidecar's: the vault dies with the sandbox (session-scoped by
// construction). Docker pause/resume keeps it; a sidecar restart or snapshot-restore
// loses it, so `installVault` is idempotent (replace) and the resume path re-installs
// from a FRESH manifest rather than anything kept on this host.
//
// Two facts the MINTER must respect (learned live, CV1): the sidecar injects headers only —
// it never rewrites the destination host, so a `gateway`-delivered git credential also
// needs the repo URL pointed at the gateway's route; and GitHub's git smart-HTTP endpoint
// rejects `Bearer` (its REST API accepts it) — a git binding is `basic` with the value
// pre-encoded as base64("x-access-token:<token>").
import { endpointWithHeaders } from "./opensandbox.js";

const EGRESS_PORT = 18080;
const log = (...a: unknown[]) => console.log("[vault]", ...a);

export type VaultAuth =
  | { type: "bearer"; credential: string }
  | { type: "basic"; credential: string }
  | { type: "apiKey"; name: string; credential: string }
  | { type: "customHeaders"; headers: { name: string; credential: string }[] };

export interface VaultBinding {
  name: string;
  hosts: string[];
  paths?: string[]; // sidecar default: ["/*"]
  methods?: string[]; // sidecar default: GET POST PUT PATCH DELETE
  schemes?: ("https" | "http")[]; // sidecar default: ["https"]
  auth: VaultAuth;
}

export interface VaultManifest {
  credentials: { name: string; value: string }[];
  bindings: VaultBinding[];
  // NON-secret env the tools need to route through the bindings: base URLs pointing at a
  // gateway, placeholder keys for CLIs that refuse to start with an empty one. Validated
  // like any launch var (see launch.ts) — it rides the container env, so it must hold
  // nothing worth stealing. The sidecar REPLACES an existing auth header, so a
  // placeholder never reaches the upstream.
  env?: Record<string, string>;
}

// Non-secret summary the session record keeps (what's installed, never the values).
export interface VaultSummary {
  revision: number;
  credentials: string[];
  bindings: string[];
}

const NAME_RE = /^[A-Za-z0-9._-]{1,128}$/;
const HEADER_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}$/;
// The sidecar refuses anything that is not an FQDN (a bare "localhost" fails the WHOLE install),
// so a dotless host is dropped here rather than sinking every other binding with it.
const HOST_RE = /^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;
const MAX_CREDENTIALS = 64;
const MAX_BINDINGS = 128;

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const strList = (v: unknown, re?: RegExp): string[] | undefined => {
  if (!Array.isArray(v)) return undefined;
  const out = v.flatMap((x) => {
    const s = str(x);
    return s && (!re || re.test(s)) ? [s] : [];
  });
  return out.length ? out : undefined;
};

function parseAuth(raw: unknown, known: Set<string>): VaultAuth | undefined {
  const a = (raw ?? {}) as Record<string, unknown>;
  const cred = str(a.credential);
  switch (a.type) {
    case "bearer":
    case "basic":
      return cred && known.has(cred) ? { type: a.type, credential: cred } : undefined;
    case "apiKey": {
      const name = str(a.name);
      return cred && known.has(cred) && name && HEADER_RE.test(name) ? { type: "apiKey", name, credential: cred } : undefined;
    }
    case "customHeaders": {
      const headers = (Array.isArray(a.headers) ? a.headers : []).flatMap((h: Record<string, unknown>) => {
        const name = str(h?.name);
        const c = str(h?.credential);
        return name && HEADER_RE.test(name) && c && known.has(c) ? [{ name, credential: c }] : [];
      });
      return headers.length ? { type: "customHeaders", headers } : undefined;
    }
    default:
      return undefined;
  }
}

// Strict parse: anything malformed is DROPPED, never guessed — a binding that injects the
// wrong credential at the wrong host is worse than a missing one. Returns undefined when
// nothing usable remains (the launch then runs without a vault at all).
export function parseVaultManifest(raw: unknown): VaultManifest | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const m = raw as Record<string, unknown>;
  const credentials: VaultManifest["credentials"] = [];
  const seen = new Set<string>();
  for (const c of Array.isArray(m.credentials) ? m.credentials : []) {
    const name = str((c as Record<string, unknown>)?.name);
    const value = typeof (c as Record<string, unknown>)?.value === "string" ? ((c as Record<string, unknown>).value as string) : "";
    if (!name || !NAME_RE.test(name) || !value || seen.has(name) || credentials.length >= MAX_CREDENTIALS) continue;
    seen.add(name);
    credentials.push({ name, value });
  }
  const bindings: VaultBinding[] = [];
  const seenB = new Set<string>();
  for (const b of Array.isArray(m.bindings) ? m.bindings : []) {
    const r = (b ?? {}) as Record<string, unknown>;
    const name = str(r.name);
    const hosts = strList(r.hosts, HOST_RE);
    const auth = parseAuth(r.auth, seen);
    if (!name || !NAME_RE.test(name) || !hosts || !auth || seenB.has(name) || bindings.length >= MAX_BINDINGS) continue;
    seenB.add(name);
    const schemes = strList(r.schemes)?.filter((s): s is "https" | "http" => s === "https" || s === "http");
    bindings.push({
      name,
      hosts,
      auth,
      ...(strList(r.paths) ? { paths: strList(r.paths) } : {}),
      ...(strList(r.methods) ? { methods: strList(r.methods)!.map((x) => x.toUpperCase()) } : {}),
      ...(schemes?.length ? { schemes } : {}),
    });
  }
  const env: Record<string, string> = {};
  if (m.env && typeof m.env === "object") {
    for (const [k, v] of Object.entries(m.env as Record<string, unknown>)) if (typeof v === "string") env[k] = v;
  }
  if (!credentials.length || !bindings.length) return undefined;
  return { credentials, bindings, ...(Object.keys(env).length ? { env } : {}) };
}

// Does any binding cover this URL's host? Used by the clone path: a host the vault
// fronts gets NO askpass/token of its own — the sidecar authenticates the request.
export function vaultCoversHost(vault: VaultManifest | undefined, url: string): boolean {
  if (!vault) return false;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return vault.bindings.some((b) =>
    b.hosts.some((h) => {
      const hh = h.toLowerCase();
      return hh.startsWith("*.") ? host.endsWith(hh.slice(1)) || host === hh.slice(2) : host === hh;
    }),
  );
}

// The create-time knobs the sidecar needs. Allow-all egress for now: dev sandboxes need
// the whole internet (npm, pip, docs); the sidecar logs a warning and injection still
// works. Upstream intends to require default-deny later — that's when the workspace
// declares its allowlist.
export const sidecarCreateSpec = () => ({
  networkPolicy: { defaultAction: "allow" as const, egress: [] as { action: string; target: string }[] },
  credentialProxy: { enabled: true },
});

const toSidecar = (m: VaultManifest) => ({
  credentials: m.credentials.map((c) => ({ name: c.name, source: { type: "inline", value: c.value } })),
  bindings: m.bindings.map((b) => ({
    name: b.name,
    match: { hosts: b.hosts, ...(b.paths ? { paths: b.paths } : {}), ...(b.methods ? { methods: b.methods } : {}), ...(b.schemes ? { schemes: b.schemes } : {}) },
    auth: b.auth,
  })),
});

async function vaultUrl(sandboxId: string): Promise<{ url: string; headers: Record<string, string> }> {
  const ep = await endpointWithHeaders(sandboxId, EGRESS_PORT);
  return { url: `http://${ep.host}${ep.basePath}/credential-vault`, headers: ep.headers };
}

const summarize = (m: VaultManifest, revision: number): VaultSummary => ({
  revision,
  credentials: m.credentials.map((c) => c.name),
  bindings: m.bindings.map((b) => `${b.name}→${b.hosts.join(",")}`),
});

// Install (or replace) the sandbox's vault. Idempotent: a vault already present is
// deleted first, so a resume/re-mint lands cleanly. The sidecar answers with its sanitized
// state (names + revision, never values).
export async function installVault(sandboxId: string, manifest: VaultManifest): Promise<VaultSummary> {
  const { url, headers } = await vaultUrl(sandboxId);
  const body = JSON.stringify(toSidecar(manifest));
  const post = () => fetch(url, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body });
  let r = await post();
  if (r.status === 409) {
    await fetch(url, { method: "DELETE", headers });
    r = await post();
  }
  if (!r.ok) throw new Error(`credential vault install → HTTP ${r.status}: ${(await r.text().catch(() => "")).slice(0, 200)}`);
  const state = (await r.json().catch(() => ({}))) as { revision?: number };
  const out = summarize(manifest, Number(state.revision) || 1);
  log(`${sandboxId.slice(0, 8)}: ${out.credentials.length} credential(s), ${out.bindings.length} binding(s) (rev ${out.revision})`);
  return out;
}

// Is a vault present on this sandbox right now? (404 after a sidecar restart = lost.)
export async function vaultPresent(sandboxId: string): Promise<boolean> {
  try {
    const { url, headers } = await vaultUrl(sandboxId);
    const r = await fetch(url, { headers });
    return r.ok;
  } catch {
    return false;
  }
}
