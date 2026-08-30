// isogate config — one JSON file, read on boot, written atomically on change.
// Everything a server needs to belong to an account lives here: the master token
// (loopback API auth), the pairing (backend + per-server secret), the relay
// enrollment, and how to reach the local OpenSandbox runtime.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { join } from "node:path";

export const HOME = process.env.ISOGATE_HOME ?? join(homedir(), ".isogate");
export const CONFIG_FILE = join(HOME, "config.json");
export const DATA = join(HOME, "data");
export const VIEWS_FILE = join(DATA, "views.json");

// 8090: side-by-side with a legacy isolation daemon (8088) during the migration window.
export const PORT = Number(process.env.ISOGATE_PORT ?? 8090);
export const HOST = process.env.ISOGATE_HOST ?? "127.0.0.1";

export interface Pairing {
  backendUrl: string;
  connectionId: string; // == the cloud `servers` row id
  secret: string; // heartbeat bearer + launch-envelope seal key
}

export interface Enrollment {
  provider: "cloudflared";
  mode: "quick";
}

// The public-web plane: a NAMED wildcard tunnel (`*.<domain>` → this gate) injected by
// the cloud (Cloud VMs: seeded at provision; any server: `POST /sandbox` or the launch
// body). Never hardcoded. Absent → web views are addressed as `<slug>.localhost`.
export interface SandboxConfig {
  provider: "cloudflared";
  creds: string; // the named tunnel's run token
  domain: string; // e.g. "<id>-web.run.isolation.cloud"
}

export interface OsbConfig {
  url: string; // the local opensandbox-server, loopback
  apiKey: string;
}

interface Config {
  token?: string;
  name?: string;
  pairing?: Pairing;
  enrollment?: Enrollment;
  osb?: OsbConfig;
  sandbox?: SandboxConfig;
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
// docker example config; `isogate up` will eventually mint + own the API key.
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
