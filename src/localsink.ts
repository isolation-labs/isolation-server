// The LOCAL workspace blob sink — local mode's hub. The CLI's workspace file is the
// durable store; this is the gate-side bundle cache the persistence engine talks to,
// so restore/save/sync/branch-per-session run UNCHANGED against a loopback endpoint
// (`persistence.workspace.endpoint = http://127.0.0.1:8090/local-workspaces`), exactly
// as they do against the R2 hub. Same contract: GET/PUT {endpoint}/{workspaceId},
// ETag = sha256(content), If-Match / If-None-Match:* compare-and-swap → 412, 304 on
// If-None-Match hit. Bundles land in HOME/overlay/<id>.bundle (0600).
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "./config.js";

const DIR = join(HOME, "overlay");
const safe = (s: string): string | undefined => (/^[A-Za-z0-9._-]{1,128}$/.test(s) ? s : undefined);
const pathFor = (id: string): string => join(DIR, `${id}.bundle`);
const etagOf = (buf: Buffer): string => `"${createHash("sha256").update(buf).digest("hex")}"`;

export function readLocalBlob(id: string): { bytes: Buffer; etag: string } | undefined {
  const k = safe(id);
  if (!k) return undefined;
  try {
    const bytes = readFileSync(pathFor(k));
    return { bytes, etag: etagOf(bytes) };
  } catch {
    return undefined;
  }
}

// CAS write: `ifMatch` must equal the current ETag (or `ifNoneMatchStar` requires
// absence). Returns the new ETag, or "conflict" — the local twin of R2's 412.
export function writeLocalBlob(id: string, bytes: Buffer, ifMatch?: string, ifNoneMatchStar = false): { etag: string } | "conflict" | undefined {
  const k = safe(id);
  if (!k) return undefined;
  const cur = readLocalBlob(k);
  if (ifNoneMatchStar && cur) return "conflict";
  if (ifMatch && (!cur || cur.etag !== ifMatch)) return "conflict";
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const p = pathFor(k);
  const tmp = `${p}.tmp`;
  writeFileSync(tmp, bytes, { mode: 0o600 });
  renameSync(tmp, p);
  return { etag: etagOf(bytes) };
}
