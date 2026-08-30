// Auto-provision cloudflared (the relay binary) — the one `connect` prerequisite a
// user would otherwise install by hand. When nothing runnable exists we fetch the
// pinned static build into the gate-managed bin (~/.isogate/bin), checksum-verified
// against the release's published digests, atomically swapped in, no root needed.
// Resolution: ISOGATE_CLOUDFLARED override → managed bin → PATH. Only the managed
// slot is ever written; a user-supplied binary is never touched.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME } from "./config.js";

export const CLOUDFLARED_VERSION = "2026.7.2";
// sha256 per asset from the GitHub release's published digests. macOS builds ship as a
// tarball holding the single binary; linux builds are the raw binary.
const ASSETS: Record<string, { asset: string; sha256: string; tgz?: true }> = {
  "linux-x64": { asset: "cloudflared-linux-amd64", sha256: "ec905ea7b7e327ff8abdde8cb64697a2152de74dbcdbf6aec9db8364eb3886cd" },
  "linux-arm64": { asset: "cloudflared-linux-arm64", sha256: "405df476437e027fc6d18729a5a77155c0a33a6082aeee60a799a688f3052e66" },
  "darwin-x64": { asset: "cloudflared-darwin-amd64.tgz", sha256: "4ee0d3b48a990a2f9b5faec5838f73ec1f400aa8e0a4864be576adfafec406cb", tgz: true },
  "darwin-arm64": { asset: "cloudflared-darwin-arm64.tgz", sha256: "2086e51c61d6565781d84117a5007d0c826d03ffdc74acb91c08c167f9f8cd7c", tgz: true },
};

const BIN_DIR = join(HOME, "bin");
const MANAGED = join(BIN_DIR, "cloudflared");
const MARKER = join(BIN_DIR, "cloudflared.version");

const runnable = (bin: string): boolean => !spawnSync(bin, ["--version"], { stdio: "ignore" }).error;
const installedVersion = (): string | undefined => {
  try {
    return readFileSync(MARKER, "utf8").trim();
  } catch {
    return undefined;
  }
};

// Resolve a runnable cloudflared, downloading into the managed slot when there is
// none. Returns the path/command to spawn.
export async function ensureCloudflared(log: (m: string) => void = () => {}): Promise<string> {
  const override = process.env.ISOGATE_CLOUDFLARED;
  if (override) {
    if (!runnable(override)) throw new Error(`ISOGATE_CLOUDFLARED points at '${override}' but it can't be run`);
    return override;
  }
  if (existsSync(MANAGED) && runnable(MANAGED)) {
    if (installedVersion() !== CLOUDFLARED_VERSION) {
      try {
        await download(log);
      } catch (e) {
        log(`cloudflared refresh failed (keeping the current binary): ${String((e as Error)?.message ?? e)}`);
      }
    }
    return MANAGED;
  }
  if (runnable("cloudflared")) return "cloudflared";
  await download(log);
  return MANAGED;
}

async function download(log: (m: string) => void): Promise<void> {
  const key = `${process.platform}-${process.arch}`;
  const a = ASSETS[key];
  if (!a) {
    throw new Error(
      `cloudflared not found and there is no prebuilt binary for ${key} — install it ` +
        `(https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) or set ISOGATE_CLOUDFLARED`,
    );
  }
  const url = `https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/${a.asset}`;
  log(`downloading cloudflared ${CLOUDFLARED_VERSION} (${a.asset})…`);
  const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(180_000) });
  if (!res.ok) throw new Error(`cloudflared download failed: HTTP ${res.status} (${url})`);
  const buf = Buffer.from(await res.arrayBuffer());
  const digest = createHash("sha256").update(buf).digest("hex");
  if (digest !== a.sha256) throw new Error(`cloudflared checksum mismatch for ${a.asset}: got ${digest}, expected ${a.sha256}`);
  mkdirSync(BIN_DIR, { recursive: true });
  const tmp = join(BIN_DIR, `.cloudflared.${process.pid}.tmp`);
  try {
    if (a.tgz) untgzBinary(buf, tmp);
    else writeFileSync(tmp, buf);
    chmodSync(tmp, 0o755);
    renameSync(tmp, MANAGED); // atomic: a concurrent spawn sees old or new, never partial
    writeFileSync(MARKER, CLOUDFLARED_VERSION);
  } finally {
    rmSync(tmp, { force: true });
  }
  log(`cloudflared ${CLOUDFLARED_VERSION} installed → ${MANAGED}`);
}

function untgzBinary(tgz: Buffer, dest: string): void {
  const dir = mkdtempSync(join(BIN_DIR, ".cloudflared-unpack-"));
  try {
    const tarball = join(dir, "cloudflared.tgz");
    writeFileSync(tarball, tgz);
    const r = spawnSync("tar", ["-xzf", tarball, "-C", dir, "cloudflared"], { stdio: "ignore" });
    if (r.status !== 0) throw new Error("failed to extract the cloudflared tarball");
    renameSync(join(dir, "cloudflared"), dest);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
