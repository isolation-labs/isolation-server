// isolation-server config — one JSON file, read on boot, written atomically on change.
// Everything a server needs to belong to an account lives here: the master token
// (loopback API auth), the pairing (backend + per-server secret), the relay
// enrollment, and how to reach the local OpenSandbox runtime.
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { join } from "node:path";

// The config home. `~/.isogate` (the pre-rename dir) is ADOPTED on first run — a paired
// box keeps its token/pairing/secrets across the rename. NEVER `~/.isolation`: old-daemon
// installs still own that dir. The old env names keep working as fallbacks (cloud-init
// from before the rename seeds ISOGATE_HOME).
function defaultHome(): string {
  const next = join(homedir(), ".isolation-server");
  const legacy = join(homedir(), ".isogate");
  try {
    if (!existsSync(next) && existsSync(legacy)) renameSync(legacy, next);
  } catch {
    /* adoption is best-effort; a fresh dir is minted below either way */
  }
  return next;
}
export const HOME = process.env.ISOLATION_SERVER_HOME ?? process.env.ISOGATE_HOME ?? defaultHome();
export const CONFIG_FILE = join(HOME, "config.json");
export const DATA = join(HOME, "data");
export const VIEWS_FILE = join(DATA, "views.json");
export const LAUNCH_SCRATCH = join(HOME, "launch", "scratch");
export const SECRETS = join(HOME, "secrets"); // 0700: sandbox-lifetime secret state (sink bearers/encKeys)

// 8090: side-by-side with a legacy isolation daemon (8088) during the migration window.
export const PORT = Number(process.env.ISOLATION_SERVER_PORT ?? process.env.ISOGATE_PORT ?? 8090);
export const HOST = process.env.ISOLATION_SERVER_HOST ?? process.env.ISOGATE_HOST ?? "127.0.0.1";

export interface Pairing {
  backendUrl: string;
  connectionId: string; // == the cloud `servers` row id
  secret: string; // heartbeat bearer + launch-envelope seal key
}

export interface Enrollment {
  provider: "cloudflared";
  // "quick" — a free trycloudflare URL that changes on restart (the heartbeat self-heals it);
  // "named" — a cloud-minted tunnel with a STABLE publicUrl (Cloud VMs, seeded at provision).
  mode: "quick" | "named";
  creds?: string; // named: the tunnel run token
  publicUrl?: string; // named: the stable public URL
}

// The public-web plane: a NAMED wildcard tunnel (`*.<domain>` → this gate) injected by
// the cloud (Cloud VMs: seeded at provision; any server: `POST /sandbox` or the launch
// body). Never hardcoded. Absent → web views are addressed as `<slug>.localhost`.
export interface SandboxConfig {
  provider?: "cloudflared";
  // The named tunnel's run token — LEGACY: a per-server public wildcard tunnel. Absent when the web
  // plane rides the private tunnel; then `domain` alone is the whole config.
  creds?: string;
  domain: string; // e.g. "isolation.cc" — web views are https://<slug>.<domain>/
}

// The SSH bastion's coords, fetched from the cloud during `connect` (POST /api/pair/bastion) and
// written here. It is what turns `ssh -p <port> root@<host>` into `ssh <routeId>@<publicHost>`: a
// public edge that routes by SSH username, reached over an outbound control connection this server
// parks — so no host IP and no port is ever handed to a user. Absent = no bastion; ssh then works
// only through the local per-session forwarder (sshfwd.ts).
export interface BastionConfig {
  controlHost: string;
  controlPort: number;
  publicHost: string; // what users type: ssh <routeId>@<publicHost>
  edgePort: number;
  daemonLabel: string; // the control-plane username — our connectionId, so the edge can recompute our token
  smbHost?: string;
  registerSecret: string; // per-connection token: HMAC(cloud signing key, daemonLabel)
  // The bastion's SSH host public key, base64 of the raw blob — PINNED. ssh2 accepts any host key
  // unless told otherwise, and this is the connection that carries our register credential and is
  // trusted to push an agent key into every sandbox, so it is pinned on first sight (or to what
  // the cloud handed down) and anything else is refused. See bastion.ts.
  hostKey?: string;
}

// The server's PRIVATE named tunnel. The cloud hands it out at pairing (or seeds it on a Cloud VM)
// from its pre-minted POOL: the Worker holds one `vpc_networks` binding per pool slot, so the tunnel
// itself identifies this server and there is nothing else to configure. We run `cloudflared tunnel
// run` with `creds` in TUNNEL_TOKEN (never argv — `ps` is world-readable) and serve the ordinary
// 127.0.0.1:8090 listener; the server has NO public URL and needs no address of its own.
//
// It used to carry an `ip` too — a loopback address unique to this server account-wide — because the
// Worker selected servers by ip through one shared binding. That required `sudo ifconfig lo0 alias`
// on macOS and broke on every reboot. Slots removed it; an `ip` on disk from an older build is
// ignored.
export interface VpcConfig {
  creds: string; // the named tunnel's run token
}

export interface OsbConfig {
  url: string; // the local opensandbox-server, loopback
  apiKey: string;
}

interface Config {
  token?: string;
  name?: string;
  machineId?: string; // this install's stable identity across pairings (PLAN §5d follow-up: no duplicate server rows)
  pairing?: Pairing;
  enrollment?: Enrollment;
  osb?: OsbConfig;
  sandbox?: SandboxConfig;
  bastion?: BastionConfig;
  vpc?: VpcConfig;
}

let cfg: Config = {};

function load(): void {
  try {
    cfg = JSON.parse(readFileSync(CONFIG_FILE, "utf8")) as Config;
  } catch {
    cfg = {};
  }
}
load();

function persist(): void {
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  const tmp = `${CONFIG_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  renameSync(tmp, CONFIG_FILE);
}

// The master token authorizes the loopback API (and signs view tokens). Minted once,
// on first boot — never transmitted anywhere except to the cloud at pair time (which
// stores it encrypted and uses it to probe /status through the tunnel).
export function getToken(): string {
  if (!cfg.token) {
    cfg.token = randomBytes(24).toString("hex");
    persist();
  }
  return cfg.token;
}

export function tokenMatches(candidate: string | undefined): candidate is string {
  return !!candidate && candidate === getToken();
}

export function getName(): string {
  return cfg.name ?? hostname();
}

export const getPairing = (): Pairing | undefined => cfg.pairing;
// A stable identity for THIS install, minted once and kept across disconnect/connect and cloud
// switches, so the cloud can recognise a machine pairing again and reuse its `servers` row
// (sessions reference that row) instead of minting a duplicate.
export function getMachineId(): string {
  if (!cfg.machineId) {
    cfg.machineId = randomUUID();
    persist();
  }
  return cfg.machineId;
}

export function savePairing(p: Pairing | undefined): void {
  cfg.pairing = p;
  persist();
}

export const getEnrollment = (): Enrollment | undefined => cfg.enrollment;
export function saveEnrollment(e: Enrollment | undefined): void {
  cfg.enrollment = e;
  persist();
}

// The OpenSandbox runtime this gate fronts. Defaults match `opensandbox-server`'s
// docker example config; `isolation-server up` will eventually mint + own the API key.
export function getOsb(): OsbConfig {
  return cfg.osb ?? { url: "http://127.0.0.1:8080", apiKey: "" };
}
export const getSandbox = (): SandboxConfig | undefined => cfg.sandbox;
export function saveSandbox(sb: SandboxConfig | undefined): void {
  cfg.sandbox = sb;
  persist();
}

export function saveOsb(o: OsbConfig): void {
  cfg.osb = o;
  persist();
}

export const getVpc = (): VpcConfig | undefined => cfg.vpc;
export function saveVpc(v: VpcConfig | undefined): void {
  cfg.vpc = v;
  persist();
}

export const getBastion = (): BastionConfig | undefined => cfg.bastion;
export function saveBastion(b: BastionConfig | undefined): void {
  cfg.bastion = b;
  persist();
}

const LOOPBACK_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;
export const isLoopbackOrigin = (u: string): boolean => LOOPBACK_ORIGIN.test(u.trim().replace(/\/+$/, ""));

// CORS: any loopback origin (local web dev on any port), plus the paired backend's
// origin (the SaaS drives us through the browser over the tunnel).
export function originAllowed(origin: string): boolean {
  if (isLoopbackOrigin(origin)) return true;
  const p = getPairing();
  if (!p) return false;
  try {
    return new URL(origin).origin === new URL(p.backendUrl).origin;
  } catch {
    return false;
  }
}

export function ensureDataDir(): void {
  if (!existsSync(DATA)) mkdirSync(DATA, { recursive: true, mode: 0o700 });
}
