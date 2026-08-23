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
import { run, writeFile } from "./execd.js";

const log = (...a: unknown[]) => console.log("[persist]", ...a);

const BUNDLE = "/tmp/.iso-workspace.bundle";

export interface WorkspaceSink {
  endpoint: string; // {endpoint}/{workspaceId} is the blob URL
  creds?: string; // bearer
  workspaceId: string;
}

interface SinkState {
  sink: WorkspaceSink;
  etag?: string;
  sessionBranch: string;
}

// Per-sandbox persistence state, session-transient by design (a gate restart
// re-reads nothing: save calls re-arrive from the web with the envelope — v1 keeps
// it in memory and accepts that a gate restart needs a relaunch to save again).
const state = new Map<string, SinkState>();

export const sinkFor = (sandboxId: string): SinkState | undefined => state.get(sandboxId);
export const dropSink = (sandboxId: string): void => void state.delete(sandboxId);

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
    const bytes = Buffer.from(await r.arrayBuffer());
    await writeFile(sandboxId, BUNDLE, bytes, 0o600);
    // Reconstitute the bundle's git INTO the existing /workspace (which may already
    // hold fresh clones). Init on a placeholder branch — git refuses to fetch into
    // the checked-out ref, so main must not be current during the fetch. Each step
    // is its own call: a failure must THROW, never silently leave a fresh repo (a
    // swallowed fetch error here would fork the workspace history).
    await sh(sandboxId, `git init -q -b _iso_restore .`);
    await sh(sandboxId, `git fetch -q ${BUNDLE} 'refs/*:refs/*'`);
    await sh(sandboxId, `git checkout -q main`);
    state.set(sandboxId, { sink, etag: r.headers.get("etag") ?? undefined, sessionBranch });
    log(`${sandboxId.slice(0, 8)}: restored bundle (etag ${r.headers.get("etag") ?? "none"})`);
  } else if (r.status === 404) {
    await sh(sandboxId, `git init -q -b main .`);
    state.set(sandboxId, { sink, etag: undefined, sessionBranch });
    log(`${sandboxId.slice(0, 8)}: new workspace (no bundle yet)`);
  } else {
    throw new Error(`workspace bundle fetch → HTTP ${r.status}`);
  }
  // v1: repos own their history — exclude them from the workspace tree.
  const ignores = [".iso-*", ...repoNames.map((n) => `/${n}/`)].join("\n");
  await writeFile(sandboxId, "/workspace/.gitignore", `${ignores}\n`, 0o644);
  await sh(sandboxId, `git add .gitignore && git -c user.name=isolation -c user.email=iso@local commit -q -m "session setup" --allow-empty`);
  await sh(sandboxId, `git checkout -q -B ${sessionBranch} main && rm -f ${BUNDLE}`);
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
  const bytes = Buffer.from(await dl.arrayBuffer());
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
  await run(sandboxId, `rm -f ${BUNDLE}`, { cwd: "/workspace" });
  log(`${sandboxId.slice(0, 8)}: saved (etag ${etag ?? "none"})`);
  return { etag };
}
