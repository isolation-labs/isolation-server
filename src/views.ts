// View registry + view-scoped tokens.
// A view = one port of one sandbox, addressable as /v/<viewId>/* through the doorman.
// Registry is a flat file: cache-tier state (rebuildable; the cloud owns truth).
//
// View tokens (ported contract from the isolation daemon): HMAC-signed with the
// master token, so the browser never carries full authority. Format <body>.<mac>,
// body = base64url(JSON {v: viewId, exp: unixSeconds}).
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { VIEWS_FILE, ensureDataDir, getToken } from "./config.js";

export type ViewType = "terminal" | "code" | "web" | "directory" | "agent";

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
  slug?: string; // web: the PUBLIC hostname label (unguessable, ≥128-bit) — the view's address on the sandbox plane
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

export function addView(sandboxId: string, type: ViewType, port: number, extra: Pick<View, "label" | "specKey" | "appPath" | "appPort" | "slug" | "agentId"> = {}): View {
  const v: View = { id: `v-${randomBytes(6).toString("hex")}`, sandboxId, type, port, ...extra };
  views[v.id] = v;
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
// 26 base32 chars = 130 bits: a web view's slug IS its public, unauthenticated address.
export const newWebSlug = (): string => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  return [...randomBytes(26)].map((b) => alphabet[b % 32]).join("");
};
export const viewsForSandbox = (sandboxId: string): View[] => Object.values(views).filter((v) => v.sandboxId === sandboxId);

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
