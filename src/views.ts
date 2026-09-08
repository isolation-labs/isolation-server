// View registry + view-scoped tokens.
// A view = one port of one sandbox, addressable as /v/<viewId>/* through the doorman.
// Registry is a flat file: cache-tier state (rebuildable; the cloud owns truth).
//
// View tokens (ported contract from the isolation daemon): HMAC-signed with the
// master token, so the browser never carries full authority. Format <body>.<mac>,
// body = base64url(JSON {v: viewId, exp: unixSeconds}).
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { VIEWS_FILE, ensureDataDir, getPairing, getToken, getVpc } from "./config.js";

export type ViewType = "terminal" | "code" | "web" | "directory" | "agent";

// Terminal appearance (the web's resolved user preference, handed inline): the xterm.js theme
// palette + font, forwarded to ttyd as client options. Whitelisted in launch.ts before it
// ever reaches a command line.
export interface TerminalStyle {
  theme?: Record<string, string>;
  fontSize?: number;
  fontFamily?: string;
}

export interface View {
  id: string;
  sandboxId: string;
  type: ViewType;
  port: number; // the port INSIDE the sandbox this view fronts
  label?: string; // display name
  specKey?: string; // the workspace-level view id (layout binding across launches)
  appPath?: string; // web: subpage the view opens on
  appPort?: number; // web: the app's OWN port (view.port is the forwarder's shadow port)
  agentId?: string; // agent: the roster DEFINITION id this view is a window onto
  dir?: string; // terminal/directory: the subtree under /workspace (the shell's cwd / the browse root)
  command?: string; // terminal: typed into the view's tmux session once, at creation
  style?: TerminalStyle; // terminal: the appearance ttyd was started with (restyle restarts ttyd)
  slug?: string; // web: the PUBLIC hostname label `<prefix>-<random tail>` (newWebSlug) — the view's address on the sandbox plane
  sshRouteId?: string; // the SSH username an end-user types: `ssh <sshRouteId>@<bastion>`. Stable across restarts.
}

let views: Record<string, View> = {};
try {
  views = JSON.parse(readFileSync(VIEWS_FILE, "utf8")) as Record<string, View>;
} catch {
  views = {};
}

function persist(): void {
  ensureDataDir();
  const tmp = `${VIEWS_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(views, null, 2), { mode: 0o600 });
  renameSync(tmp, VIEWS_FILE);
}

export function addView(sandboxId: string, type: ViewType, port: number, extra: Pick<View, "label" | "specKey" | "appPath" | "appPort" | "slug" | "agentId" | "dir" | "command" | "style"> = {}): View {
  const v: View = { id: `v-${randomBytes(6).toString("hex")}`, sandboxId, type, port, ...extra };
  views[v.id] = v;
  persist();
  return v;
}

// Patch display/appearance fields in place (label, style). `undefined` clears a field.
export function updateView(id: string, patch: Partial<Pick<View, "label" | "style">>): View | undefined {
  const v = views[id];
  if (!v) return undefined;
  for (const [k, val] of Object.entries(patch)) {
    if (val === undefined) delete (v as unknown as Record<string, unknown>)[k];
    else (v as unknown as Record<string, unknown>)[k] = val;
  }
  persist();
  return v;
}

export function dropView(id: string): View | undefined {
  const v = views[id];
  if (v) {
    delete views[id];
    persist();
  }
  return v;
}

export const getView = (id: string): View | undefined => views[id];
export const viewBySlug = (slug: string): View | undefined => Object.values(views).find((v) => v.type === "web" && v.slug === slug);
// A web view's slug IS its public, unauthenticated address, and it is also the ROUTE: the Worker
// reaches this server over the binding for its pool slot, and the slug carries an OPAQUE prefix the
// cloud derived from that slot (`<prefix>-<tail>`, config.ts VpcConfig.previewPrefix) so the Worker
// routes `<slug>.<domain>` from the label alone — no lookup, no table, nothing for the heartbeat to
// report, and the slot number itself never appears. Only THIS server's doorman knows the tail, so a
// recycled slot or a guessed prefix reaches a doorman that answers "unknown app" (404).
// The tail is the whole secret: 26 base32 chars = 130 bits, preserving the minimum 128-bit
// public-address invariant independently of the shared routing prefix. No prefix (unpaired, or a
// backend without a pool) → the bare tail, reachable at `<tail>.localhost` only.
export const SLUG_TAIL_LEN = 26;
const PREFIX_RE = /^[a-z2-7]{6,16}$/;
export const newWebSlug = (prefix: string | undefined = getVpc()?.previewPrefix): string => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const tail = [...randomBytes(SLUG_TAIL_LEN)].map((b) => alphabet[b % 32]).join("");
  return typeof prefix === "string" && PREFIX_RE.test(prefix) ? `${prefix}-${tail}` : tail;
};
export const viewsForSandbox = (sandboxId: string): View[] => Object.values(views).filter((v) => v.sandboxId === sandboxId);

// The view's route id, minted once and PERSISTED: a user's saved `ssh <id>@host` has to keep
// working across restarts of this server and of the bastion, so it can never be regenerated.
//
// Namespaced by a stable hash of our pairing connectionId, because the bastion is SHARED across
// every server on the cloud: two servers minting the same id would collide there. The namespace
// makes that impossible rather than improbable. Unpaired (self-host) → all-random, nothing to
// collide with. This is a ROUTING key, not a secret — the edge still verifies the user's key.
export function ensureRouteId(id: string): string | undefined {
  const v = views[id];
  if (!v) return undefined;
  if (!v.sshRouteId) {
    // Never hand two views the same id. The bastion keys its route table on it, so a duplicate
    // would replace the older route outright: one view's saved `ssh <id>@host` would land in the
    // other view's shell, governed by the other view's key allow-list.
    let candidate = "";
    do {
      candidate = `${connNamespace()}${randBase36(v.type === "web" ? 25 : 4)}`;
    } while (viewByRouteId(candidate));
    v.sshRouteId = candidate;
    persist();
  }
  return v.sshRouteId;
}

export const viewByRouteId = (routeId: string): View | undefined => Object.values(views).find((v) => v.sshRouteId === routeId);

const B36 = "0123456789abcdefghijklmnopqrstuvwxyz";
// Uniform base36 by rejection sampling: `byte % 36` would bias toward 0-3 (256 = 7*36 + 4) and
// shave entropy off an id that is also used as a public label.
function randBase36(n: number): string {
  let out = "";
  while (out.length < n) {
    for (const b of randomBytes(n - out.length + 8)) {
      if (b >= 252) continue;
      out += B36[b % 36];
      if (out.length === n) break;
    }
  }
  return out;
}
// A stable 6-char namespace derived from our connectionId (empty when unpaired).
function connNamespace(): string {
  const id = getPairing()?.connectionId;
  if (!id) return "";
  return BigInt(`0x${createHash("sha256").update(id).digest("hex")}`).toString(36).padStart(6, "0").slice(0, 6);
}

export function dropViewsForSandbox(sandboxId: string): void {
  for (const v of viewsForSandbox(sandboxId)) delete views[v.id];
  persist();
}

// --- view tokens ---------------------------------------------------------

interface Payload {
  v: string;
  exp: number;
}

const sign = (body: string): string => createHmac("sha256", getToken()).update(body).digest("base64url");

export function mintViewToken(viewId: string, ttlSec = 3600): string {
  const body = Buffer.from(JSON.stringify({ v: viewId, exp: Math.floor(Date.now() / 1000) + ttlSec } satisfies Payload)).toString("base64url");
  return `${body}.${sign(body)}`;
}

export function verifyViewToken(token: string | undefined, viewId: string): boolean {
  if (!token || !token.includes(".")) return false;
  const [body, mac] = token.split(".");
  const a = Buffer.from(mac);
  const b = Buffer.from(sign(body));
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Payload;
    return p.v === viewId && p.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}
