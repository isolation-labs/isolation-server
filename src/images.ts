// Session images (PLAN O4). A workspace runs from `isolation-server-spec:<wsHash>` = FROM <base>
// + our tooling layer. The base is, in order: a host-side `devcontainer build` result
// (Dockerfile/build/features configs), else the config's pre-built image, else the
// language image analysis picked, else DEFAULT_BASE. Built ONCE per workspace hash with
// the host's docker CLI (the gate runs on the Docker host); OpenSandbox then launches it.
import { spawnSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { hostClone, type AnalysisRepo, type LaunchSpec } from "./analysis.js";
import { HOME } from "./config.js";

const log = (...a: unknown[]) => console.log("[images]", ...a);

// The launch's `persistence.cache` envelope: a registry the SaaS provisions so a FRESH
// Cloud VM pulls spec/cache images built elsewhere instead of rebuilding. Images are
// addressed `<registry>/<repository>:<kind>-<hash>`; creds (when given) are used for a
// per-process `docker login` and never logged.
export interface ImageRegistry {
  registry: string;
  repository: string;
  username?: string;
  password?: string;
}

const remoteRef = (r: ImageRegistry, localTag: string): string => `${r.registry.replace(/\/+$/, "")}/${r.repository}:${localTag.replace(":", "-")}`;

// Registry ops run with their OWN docker config dir, not the user's ~/.docker: the user's
// config may name a credential helper (Docker Desktop's `desktop`/`osxkeychain`) that
// blocks waiting on a keychain/GUI session when invoked from a login service — a pull of
// even a missing tag then hangs. Our dir has no credsStore; when the envelope carries
// creds, `docker login` writes them into THIS dir only (0700, gate-owned, per registry).
function dockerEnv(r: ImageRegistry): NodeJS.ProcessEnv {
  const dir = join(DOCKER_CFG_ROOT, createHash("sha256").update(r.registry).digest("hex").slice(0, 16));
  if (!existsSync(join(dir, "config.json"))) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, "config.json"), "{}", { mode: 0o600 });
  }
  return { ...process.env, DOCKER_CONFIG: dir };
}
const loggedIn = new Set<string>();
function dockerLogin(r: ImageRegistry, env: NodeJS.ProcessEnv): void {
  if (!r.username || !r.password || loggedIn.has(r.registry)) return;
  const p = spawnSync("docker", ["login", r.registry, "-u", r.username, "--password-stdin"], { input: r.password, env, stdio: ["pipe", "ignore", "ignore"] });
  if (p.status === 0) loggedIn.add(r.registry);
}

// Pull `<localTag>` from the registry (tagging it locally) — true on success. Async:
// a multi-GB pull must never block the gate's event loop (heartbeats, views).
export async function pullImage(r: ImageRegistry, localTag: string): Promise<boolean> {
  const env = dockerEnv(r);
  dockerLogin(r, env);
  const ref = remoteRef(r, localTag);
  // Hard cap: a registry that neither answers nor fails (seen with Docker Desktop and a
  // loopback registry) must never wedge a launch — give up and build locally instead.
  const ok = await new Promise<boolean>((resolve) => {
    const p = spawn("docker", ["pull", "-q", ref], { stdio: "ignore", env });
    const t = setTimeout(() => {
      log(`pull of ${localTag} timed out — building locally`);
      p.kill("SIGKILL");
    }, PULL_TIMEOUT_MS);
    p.on("error", () => { clearTimeout(t); resolve(false); });
    p.on("exit", (code) => { clearTimeout(t); resolve(code === 0); });
  });
  if (!ok) return false;
  spawnSync("docker", ["tag", ref, localTag], { stdio: "ignore" });
  log(`pulled ${localTag} from ${r.registry}`);
  return true;
}

// Push in the background — a launch never waits on a push.
export function pushImageInBackground(r: ImageRegistry, localTag: string): void {
  const env = dockerEnv(r);
  dockerLogin(r, env);
  const ref = remoteRef(r, localTag);
  spawnSync("docker", ["tag", localTag, ref], { stdio: "ignore" });
  const p = spawn("docker", ["push", "-q", ref], { stdio: "ignore", env });
  p.on("exit", (code) => log(code === 0 ? `pushed ${localTag} → ${r.registry}` : `push of ${localTag} failed (${code})`));
  p.on("error", () => log(`push of ${localTag} failed to start`));
}

// Multi-arch, apt-based, git + a non-root user: what a workspace with no detectable
// language gets. Batteries (Node/Python) come from analysis-picked images, not here.
export const DEFAULT_BASE = "mcr.microsoft.com/devcontainers/base:ubuntu";
const NODE_VERSION = "22.14.0";
const TTYD_VERSION = "1.7.7";
const FILEBROWSER_VERSION = "2.63.16";
const DEVCONTAINER_CLI_VERSION = "0.80.0";
const PULL_TIMEOUT_MS = 10 * 60_000;
const DOCKER_CFG_ROOT = join(HOME, "docker-config");

export const specImageTag = (wsHash: string) => `isolation-server-spec:${wsHash.slice(0, 32)}`;
const devcImageTag = (wsHash: string) => `isolation-server-devc:${wsHash.slice(0, 32)}`;

export function imageExists(tag: string): boolean {
  return spawnSync("docker", ["image", "inspect", tag], { stdio: "ignore" }).status === 0;
}

// The tooling layer every session gets, whatever its base: git/tmux (clones, terminal
// mirror), a static Node bundled as `iso-node` (the web-view forwarder — exposed as
// node/npm only when the base has none), ttyd, code-server, filebrowser. Every fetch is
// arch-matched and the optional ones are guarded so an exotic base degrades a view
// instead of failing the build.
export function specDockerfile(base: string): string {
  return `FROM ${base}
USER root
RUN (command -v apt-get >/dev/null && apt-get update && apt-get install -y --no-install-recommends \\
      git tmux curl ca-certificates procps openssh-client xz-utils && rm -rf /var/lib/apt/lists/*) || true
RUN set -eux; ARCH="$(uname -m)"; case "$ARCH" in x86_64) N=x64;; aarch64|arm64) N=arm64;; *) N="$ARCH";; esac; \\
    mkdir -p /opt/iso; curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-$N.tar.gz" | tar -xz -C /opt/iso --strip-components=1; \\
    ln -sf /opt/iso/bin/node /usr/local/bin/iso-node; \\
    if ! command -v node >/dev/null 2>&1; then for b in node npm npx corepack; do ln -sf /opt/iso/bin/$b /usr/local/bin/$b; done; fi
RUN set -eux; ARCH="$(uname -m)"; case "$ARCH" in x86_64) T=x86_64;; aarch64|arm64) T=aarch64;; *) T="$ARCH";; esac; \\
    curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.$T" && chmod +x /usr/local/bin/ttyd
RUN (curl -fsSL https://code-server.dev/install.sh | sh -s -- --method=standalone --prefix=/opt/iso-code \\
      && ln -sf /opt/iso-code/bin/code-server /usr/local/bin/code-server) || true
RUN (set -eux; ARCH="$(uname -m)"; case "$ARCH" in x86_64) F=amd64;; aarch64|arm64) F=arm64;; *) F="$ARCH";; esac; \\
    curl -fsSL "https://github.com/filebrowser/filebrowser/releases/download/v${FILEBROWSER_VERSION}/linux-$F-filebrowser.tar.gz" | tar -xz -C /usr/local/bin filebrowser \\
    && chmod +x /usr/local/bin/filebrowser) || true
RUN mkdir -p /workspace
WORKDIR /workspace
`;
}

function needsDevcontainerBuild(spec: LaunchSpec): boolean {
  const d = spec.devContainer;
  if (d.features && Object.keys(d.features).length) return true;
  if (spec.source !== "repository") return false;
  return Boolean(d.dockerFile || d.build || d.dockerComposeFile);
}

// Host-side `devcontainer build` (Dockerfile/build/features). The CLI is fetched on
// demand with npx (pinned) — not a runtime dependency of the gate. Any failure returns
// undefined → the caller falls back (image / language base), never blocks the launch.
async function buildDevcontainerBase(spec: LaunchSpec, repos: AnalysisRepo[], wsHash: string, onLine?: (l: string) => void): Promise<string | undefined> {
  if (!needsDevcontainerBuild(spec)) return undefined;
  const tag = devcImageTag(wsHash);
  if (imageExists(tag)) return tag;
  const work = mkdtempSync(join(tmpdir(), "isolation-server-devc-"));
  try {
    const folder = join(work, "ws");
    if (spec.source === "generated") {
      mkdirSync(join(folder, ".devcontainer"), { recursive: true });
      writeFileSync(join(folder, ".devcontainer", "devcontainer.json"), JSON.stringify({ ...(spec.devContainer.image ? { image: spec.devContainer.image } : {}), ...(spec.devContainer.features ? { features: spec.devContainer.features } : {}) }));
    } else {
      const repo = repos.find((r) => r.dir === spec.repoDir) ?? repos[0];
      if (!repo || !hostClone(repo.url, folder, repo.token, ["--depth", "1", ...(repo.branch ? ["--branch", repo.branch] : [])])) {
        log("devcontainer build: repo clone failed — falling back");
        return undefined;
      }
    }
    onLine?.(`devcontainer build → ${tag}`);
    const ok = await runLogged("npx", ["-y", `@devcontainers/cli@${DEVCONTAINER_CLI_VERSION}`, "build", "--workspace-folder", folder, "--image-name", tag], onLine);
    return ok && imageExists(tag) ? tag : undefined;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function runLogged(cmd: string, args: string[], onLine?: (l: string) => void): Promise<boolean> {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    const feed = (b: Buffer) => b.toString().split("\n").filter(Boolean).forEach((l) => onLine?.(l.slice(0, 200)));
    p.stdout.on("data", feed);
    p.stderr.on("data", feed);
    p.on("error", () => resolve(false));
    p.on("exit", (code) => resolve(code === 0));
  });
}

// Ensure the spec image for this workspace hash exists; returns its tag. `onLine`
// streams build output so the launch can report progress instead of an opaque wait.
export async function ensureSpecImage(spec: LaunchSpec, repos: AnalysisRepo[], wsHash: string, onLine?: (l: string) => void, registry?: ImageRegistry): Promise<string> {
  const tag = specImageTag(wsHash);
  if (imageExists(tag)) return tag;
  if (registry) {
    onLine?.("looking for a prebuilt session image");
    if (await pullImage(registry, tag)) return tag;
  }
  const base = (await buildDevcontainerBase(spec, repos, wsHash, onLine)) ?? spec.devContainer.image ?? DEFAULT_BASE;
  const ctx = mkdtempSync(join(tmpdir(), "isolation-server-spec-"));
  try {
    writeFileSync(join(ctx, "Dockerfile"), specDockerfile(base));
    onLine?.(`building session image from ${base}`);
    const ok = await runLogged("docker", ["build", "-t", tag, ctx], onLine);
    if (!ok || !imageExists(tag)) throw new Error(`session image build failed (base ${base})`);
    log(`built ${tag} from ${base}`);
    if (registry) pushImageInBackground(registry, tag);
    return tag;
  } finally {
    rmSync(ctx, { recursive: true, force: true });
  }
}

export const dockerAvailable = (): boolean => existsSync("/var/run/docker.sock") || spawnSync("docker", ["version"], { stdio: "ignore" }).status === 0;
