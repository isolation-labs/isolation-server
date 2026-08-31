// Launch-secret envelope (decrypt side) — ported contract from the isolation daemon,
// byte-compatible with the Worker's WebCrypto AES-GCM seal (cloud claude.ts):
//   `${b64url(iv)}:${b64url(ciphertext||tag)}`, 12-byte IV, 16-byte tag,
//   key = HKDF-SHA256(secret, info="isolation:claude-envelope:v1").
// The seal key is the per-server PAIRING SECRET (paired) or the MASTER TOKEN
// (manual). We try both — the GCM tag picks the right one. Keeping the label and
// format identical means the existing cloud sealing code works against isolation-server
// with zero changes.
import { createDecipheriv, hkdfSync } from "node:crypto";
import { getPairing, getToken } from "./config.js";

function unb64url(s: string): Buffer {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(pad + "=".repeat((4 - (pad.length % 4)) % 4), "base64");
}

const keyFor = (secret: string): Buffer =>
  Buffer.from(hkdfSync("sha256", Buffer.from(secret), Buffer.alloc(0), Buffer.from("isolation:claude-envelope:v1"), 32));

function tryDecrypt(blob: string, secret: string): unknown | undefined {
  const [ivPart, ctPart] = blob.split(":");
  if (!ivPart || !ctPart) return undefined;
  const iv = unb64url(ivPart);
  const data = unb64url(ctPart);
  if (data.length <= 16) return undefined;
  const tag = data.subarray(data.length - 16);
  const enc = data.subarray(0, data.length - 16);
  try {
    const d = createDecipheriv("aes-256-gcm", keyFor(secret), iv);
    d.setAuthTag(tag);
    return JSON.parse(Buffer.concat([d.update(enc), d.final()]).toString("utf8"));
  } catch {
    return undefined;
  }
}

// A sealed blob decrypts to its JSON payload; anything else (already-inline object,
// malformed string) returns undefined and callers fall back to the inline shape.
export function openEnvelope(blob: unknown): unknown | undefined {
  if (typeof blob !== "string" || !blob.includes(":")) return undefined;
  for (const secret of [getPairing()?.secret, getToken()]) {
    if (!secret) continue;
    const out = tryDecrypt(blob, secret);
    if (out !== undefined) return out;
  }
  return undefined;
}

// Accept a field that may arrive sealed (string) or inline (object) — local mode
// sends plaintext over loopback; the web always seals.
export function sealedOrInline(v: unknown): unknown {
  return typeof v === "string" ? openEnvelope(v) : v;
}
