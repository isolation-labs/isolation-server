// Workspace persistence — the permanently-ours layer (PLAN §4.5): /workspace is a
// git repo whose serialized form is a bundle in an R2-agnostic HTTP blob sink
// (`GET/PUT {endpoint}/{workspaceId}`, bearer auth, ETag compare-and-swap). The
// choreography runs INSIDE the sandbox via execd; the gate only ferries the bundle
// bytes and remembers the ETag.
//
// Branch-per-session: restore checks out `session/<sandboxId>` off main, save
// merges it back --no-ff and PUTs the new bundle with If-Match (412 → the caller
// re-pulls and retries; nothing is lost — the session branch is in the bundle).
//
// v1 scope: cloned repos keep their own git and are EXCLUDED from the workspace
// tree (.gitignore'd at restore). The `.overlay/` capture mechanism (tracking a
// repo's gitignored secrets) is the next slice.
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SECRETS } from "./config.js";
import { run, writeFile } from "./execd.js";

const log = (...a: unknown[]) => console.log("[persist]", ...a);

const BUNDLE = "/tmp/.iso-workspace.bundle";

export interface WorkspaceSink {
  endpoint: string; // {endpoint}/{workspaceId} is the blob URL
  creds?: string; // bearer
  encKey?: string; // end-to-end bundle encryption key (the sink only stores ciphertext)
  workspaceId: string;
}

// End-to-end bundle encryption — byte-compatible with the isolation daemon's
// format so bundles migrate across runtimes: `magic(8) || iv(12) || ct || tag(16)`.
//   ISOAEAD2 (current): key = HKDF-SHA256(encKey, salt=workspaceId, v2 label)
//   ISOAEAD1 (legacy, decrypt-only): key = SHA-256(encKey)
// An unmarked blob is a pre-encryption plaintext bundle → passed through.
const AEAD_MAGIC_V2 = Buffer.from("ISOAEAD2", "ascii");
const AEAD_MAGIC_V1 = Buffer.from("ISOAEAD1", "ascii");
const aesKeyV2 = (encKey: string, workspaceId: string) =>
  Buffer.from(hkdfSync("sha256", Buffer.from(encKey), Buffer.from(workspaceId), Buffer.from("isolation:workspace-bundle:v2"), 32));
const hasMagic = (buf: Buffer, magic: Buffer): boolean => buf.length >= magic.length && buf.subarray(0, magic.length).equals(magic);

function encryptBundle(buf: Buffer, encKey: string, workspaceId: string): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", aesKeyV2(encKey, workspaceId), iv);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([AEAD_MAGIC_V2, iv, ct, c.getAuthTag()]);
}

function decryptBundle(buf: Buffer, encKey: string, workspaceId: string): Buffer {
  if (!hasMagic(buf, AEAD_MAGIC_V2) && !hasMagic(buf, AEAD_MAGIC_V1)) return buf; // legacy plaintext
  const key = hasMagic(buf, AEAD_MAGIC_V2) ? aesKeyV2(encKey, workspaceId) : createHash("sha256").update(encKey).digest();
  const body = buf.subarray(AEAD_MAGIC_V2.length);
  const d = createDecipheriv("aes-256-gcm", key, body.subarray(0, 12));
  d.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([d.update(body.subarray(12, body.length - 16)), d.final()]);
}

interface SinkState {
  sink: WorkspaceSink;
  etag?: string;
  sessionBranch: string;
}

// Per-sandbox persistence state. It holds the sink's bearer + encKey, so it lives in
// the gate's 0600 secret store (HOME/secrets/sinks.json) — sandbox-lifetime only,
// dropped on finish — and survives a gate restart (a rebuild/`isogate up` mid-session
// must not strand the session's ability to save or sync).
const state = new Map<string, SinkState>();
const SINKS_FILE = join(SECRETS, "sinks.json");
try {
  for (const [k, v] of Object.entries(JSON.parse(readFileSync(SINKS_FILE, "utf8")) as Record<string, SinkState>)) state.set(k, v);
} catch {
  /* first run / nothing persisted */
}
function persistSinks(): void {
  mkdirSync(SECRETS, { recursive: true, mode: 0o700 });
  const tmp = `${SINKS_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(Object.fromEntries(state)), { mode: 0o600 });
  renameSync(tmp, SINKS_FILE);
}
function setSink(sandboxId: string, st: SinkState): void {
  state.set(sandboxId, st);
  persistSinks();
}

export const sinkFor = (sandboxId: string): SinkState | undefined => state.get(sandboxId);
export const dropSink = (sandboxId: string): void => {
  if (state.delete(sandboxId)) persistSinks();
};

const blobUrl = (s: WorkspaceSink): string => `${s.endpoint.replace(/\/+$/, "")}/${encodeURIComponent(s.workspaceId)}`;
const authHeaders = (s: WorkspaceSink): Record<string, string> => (s.creds ? { Authorization: `Bearer ${s.creds}` } : {});

async function sh(sandboxId: string, cmd: string, cwd = "/workspace"): Promise<string> {
  const r = await run(sandboxId, cmd, { cwd, timeoutMs: 180_000 });
  if (!r.ok) throw new Error(`persistence step failed: ${cmd.slice(0, 80)} → ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return r.stdout;
}

// Restore the workspace tree into a fresh sandbox: pull the bundle (404 → brand-new
// workspace, init empty), clone it as /workspace's git, then branch the session off
// main. Repo folders are excluded from tracking (v1 — see header).
export async function restoreWorkspace(sandboxId: string, sink: WorkspaceSink, repoNames: string[]): Promise<void> {
  const sessionBranch = `session/${sandboxId.slice(0, 8)}`;
  const r = await fetch(blobUrl(sink), { headers: authHeaders(sink) });
  if (r.ok) {
    let bytes: Buffer = Buffer.from(await r.arrayBuffer());
    if (sink.encKey) bytes = decryptBundle(bytes, sink.encKey, sink.workspaceId);
    await writeFile(sandboxId, BUNDLE, bytes, 0o600);
    // Reconstitute the bundle's git INTO the existing /workspace (which may already
    // hold fresh clones). Init on a placeholder branch — git refuses to fetch into
    // the checked-out ref, so main must not be current during the fetch. Each step
    // is its own call: a failure must THROW, never silently leave a fresh repo (a
    // swallowed fetch error here would fork the workspace history).
    await sh(sandboxId, `git init -q -b _iso_restore .`);
    await sh(sandboxId, `git fetch -q ${BUNDLE} 'refs/*:refs/*'`);
    await sh(sandboxId, `git checkout -q main`);
    setSink(sandboxId, { sink, etag: r.headers.get("etag") ?? undefined, sessionBranch });
    log(`${sandboxId.slice(0, 8)}: restored bundle (etag ${r.headers.get("etag") ?? "none"})`);
  } else if (r.status === 404) {
    await sh(sandboxId, `git init -q -b main .`);
    // DETERMINISTIC root commit (fixed identity + epoch date + empty tree): two
    // sessions that race the very first save of a workspace each init locally —
    // identical roots keep their histories related, so the later sync/save merges
    // instead of hitting git's unrelated-histories refusal.
    await sh(
      sandboxId,
      `GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' ` +
        `git -c user.name=isolation -c user.email=iso@local commit -q --allow-empty -m "workspace root"`,
    );
    setSink(sandboxId, { sink, etag: undefined, sessionBranch });
    log(`${sandboxId.slice(0, 8)}: new workspace (no bundle yet)`);
  } else {
    throw new Error(`workspace bundle fetch → HTTP ${r.status}`);
  }
  // Repos own their history — never tracked here (matches the daemon's shipped
  // overlay semantics; the old `.overlay/` secret capture is retired per §16
  // SEC-2 — secrets come push-only from the environment config).
  const ignores = [
    "# isolation overlay — cloned repos have their own git, never track them here",
    ...repoNames.map((n) => `/${n}/`),
    "node_modules/",
    "*.log",
    ".iso-*",
  ].join("\n");
  await writeFile(sandboxId, "/workspace/.gitignore", `${ignores}\n`, 0o644);
  await sh(sandboxId, `git add .gitignore && git -c user.name=isolation -c user.email=iso@local commit -q -m "session setup" --allow-empty`);
  await sh(sandboxId, `git checkout -q -B ${sessionBranch} main && rm -f ${BUNDLE}`);
}

// Sync: pull the hub's latest main into the RUNNING session — explicit/opt-in (it
// touches a live working tree). 304 (ETag unchanged) → nothing to do. Otherwise
// fetch the fresh bundle's main into a side ref, advance local main, and merge it
// into the session branch; a conflict aborts cleanly (409-shaped) with the session
// branch untouched.
export async function syncWorkspace(sandboxId: string, resolve = false): Promise<{ updated: boolean; etag?: string; conflict?: boolean; conflicts?: string[] }> {
  const st = state.get(sandboxId);
  if (!st) throw new Error("no persistence configured for this sandbox");
  const r = await fetch(blobUrl(st.sink), {
    headers: { ...authHeaders(st.sink), ...(st.etag ? { "If-None-Match": st.etag } : {}) },
  });
  if (r.status === 304) return { updated: false, etag: st.etag };
  if (r.status === 404) return { updated: false }; // nothing saved yet anywhere
  if (!r.ok) throw new Error(`workspace bundle fetch → HTTP ${r.status}`);
  let bytes: Buffer = Buffer.from(await r.arrayBuffer());
  if (st.sink.encKey) bytes = decryptBundle(bytes, st.sink.encKey, st.sink.workspaceId);
  await writeFile(sandboxId, BUNDLE, bytes, 0o600);
  await sh(sandboxId, `git fetch -q ${BUNDLE} main:refs/iso/hub-main`);
  await sh(sandboxId, `git branch -q -f main refs/iso/hub-main`);
  const merge = await run(sandboxId, `git -c user.name=isolation -c user.email=iso@local merge -q -m "sync from hub" main`, {
    cwd: "/workspace",
    timeoutMs: 120_000,
  });
  await run(sandboxId, `rm -f ${BUNDLE}`, { cwd: "/workspace" });
  if (!merge.ok || /CONFLICT/.test(merge.stdout + merge.stderr)) {
    if (resolve) {
      // Resolve mode (the daemon contract): keep git's conflict markers in the working
      // tree and report the conflicted paths — the client resolves them and a later
      // save completes the merge. The merge stays in progress on purpose.
      const u = await run(sandboxId, `git diff --name-only --diff-filter=U`, { cwd: "/workspace" });
      st.etag = r.headers.get("etag") ?? st.etag;
      persistSinks();
      return { updated: false, etag: st.etag, conflict: true, conflicts: u.stdout.split("\n").filter(Boolean) };
    }
    await run(sandboxId, `git merge --abort`, { cwd: "/workspace" });
    const err = new Error("sync conflict — hub changes collide with this session's work") as Error & { conflict?: boolean };
    err.conflict = true;
    throw err;
  }
  st.etag = r.headers.get("etag") ?? st.etag;
  persistSinks();
  log(`${sandboxId.slice(0, 8)}: synced to hub main (etag ${st.etag ?? "none"})`);
  return { updated: true, etag: st.etag };
}

// Abort an in-progress (resolve-mode) merge: the working tree returns to its
// pre-pull state on the session branch. Safe when no merge is running.
export async function abortMerge(sandboxId: string): Promise<void> {
  const st = state.get(sandboxId);
  await run(sandboxId, `git merge --abort || true`, { cwd: "/workspace" });
  if (st) await run(sandboxId, `git checkout -q ${st.sessionBranch} || true`, { cwd: "/workspace" });
}

// Save: commit the session branch, merge --no-ff into main, bundle everything, PUT
// with If-Match. A merge conflict aborts cleanly and reports 409-shaped info; a 412
// from the sink means someone else saved first — re-pull/re-merge is the next slice
// (v1 surfaces it to the caller).
export async function saveWorkspace(sandboxId: string): Promise<{ etag?: string }> {
  const st = state.get(sandboxId);
  if (!st) throw new Error("no persistence configured for this sandbox");
  await sh(sandboxId, `git add -A && git -c user.name=isolation -c user.email=iso@local commit -q -m "session save" --allow-empty`);
  const merge = await run(sandboxId, `git checkout -q main && git -c user.name=isolation -c user.email=iso@local merge --no-ff -q -m "merge ${st.sessionBranch}" ${st.sessionBranch}`, {
    cwd: "/workspace",
    timeoutMs: 120_000,
  });
  if (!merge.ok || /CONFLICT/.test(merge.stdout + merge.stderr)) {
    await run(sandboxId, `git merge --abort; git checkout -q ${st.sessionBranch}`, { cwd: "/workspace" });
    const err = new Error("merge conflict — the session branch is preserved; resolve via sync") as Error & { conflict?: boolean };
    err.conflict = true;
    throw err;
  }
  await sh(sandboxId, `git bundle create -q ${BUNDLE} --all && git checkout -q ${st.sessionBranch}`);
  // Ferry the bundle out through execd's download endpoint.
  const { endpointFor } = await import("./opensandbox.js");
  const ep = await endpointFor(sandboxId, 44772);
  const dl = await fetch(`http://${ep.host}/files/download?path=${encodeURIComponent(BUNDLE)}`);
  if (!dl.ok) throw new Error(`bundle download from sandbox → HTTP ${dl.status}`);
  let bytes: Buffer = Buffer.from(await dl.arrayBuffer());
  if (st.sink.encKey) bytes = encryptBundle(bytes, st.sink.encKey, st.sink.workspaceId);
  const put = await fetch(blobUrl(st.sink), {
    method: "PUT",
    headers: {
      ...authHeaders(st.sink),
      "Content-Type": "application/octet-stream",
      ...(st.etag ? { "If-Match": st.etag } : { "If-None-Match": "*" }),
    },
    body: new Uint8Array(bytes),
  });
  if (put.status === 412) {
    const err = new Error("workspace advanced remotely (ETag mismatch) — sync then save again") as Error & { conflict?: boolean };
    err.conflict = true;
    throw err;
  }
  if (!put.ok) throw new Error(`bundle PUT → HTTP ${put.status}`);
  const etag = put.headers.get("etag") ?? undefined;
  st.etag = etag;
  persistSinks();
  await run(sandboxId, `rm -f ${BUNDLE}`, { cwd: "/workspace" });
  log(`${sandboxId.slice(0, 8)}: saved (etag ${etag ?? "none"})`);
  return { etag };
}
