// Dependency cache (PLAN O4). After a session launches, build — in the BACKGROUND,
// never awaited by the launch — an image with each repo's dependencies installed,
// keyed by cacheKey(workspaceHash, dependencyHash), so later launches of the same
// project start from it and restore node_modules/.venv/vendor instead of installing.
// Deps are baked under /iso/cache/<dir> (not /workspace) so the clone into
// /workspace/<dir> never hits a non-empty dir; the launch copies them in post-clone.
// Caches are optimizations, never requirements: any failure just means "no cache".
import { cpSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { imageExists } from "./images.js";

const log = (...a: unknown[]) => console.log("[cache]", ...a);
const building = new Set<string>();

export const cacheImageTag = (key: string) => `isogate-cache:${key.slice(0, 32)}`;

const DEP_MANIFESTS = ["package.json", "requirements.txt", "pyproject.toml", "Gemfile", "composer.json", "Cargo.toml", "go.mod"];

// Repo dirs with something cacheable (present in the scratch fetch).
export function reposWithDeps(scratchDir: string, dirs: string[]): string[] {
  return dirs.filter((d) => DEP_MANIFESTS.some((f) => existsSync(join(scratchDir, d, f))));
}

// Per-repo Dockerfile fragment: copy the manifests to /iso/cache/<dir> and install
// REPO-LOCALLY (node_modules / .venv / vendor). Each install is guarded by the tool's
// presence, so a manifest whose toolchain isn't in the image self-skips (partial cache)
// instead of failing the build; a toolchain that IS present but errors fails the build.
function installFragment(scratchDir: string, dir: string): string {
  const has = (f: string) => existsSync(join(scratchDir, dir, f));
  const dest = `/iso/cache/${dir}`;
  const lines: string[] = [`RUN mkdir -p ${dest}`];
  const copy = (...files: string[]) => files.filter(has).forEach((f) => lines.push(`COPY ${dir}/${f} ${dest}/`));
  const guard = (tool: string, cmd: string) =>
    lines.push(`RUN cd ${dest} && (command -v ${tool} >/dev/null 2>&1 && ( ${cmd} ) || echo "[cache] no ${tool} in image; skipping ${dir}")`);
  if (has("package.json")) {
    copy("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock");
    const install = has("pnpm-lock.yaml")
      ? "corepack enable && pnpm install --frozen-lockfile"
      : has("yarn.lock")
        ? "corepack enable && yarn install --frozen-lockfile"
        : has("package-lock.json")
          ? "npm ci --no-audit --no-fund"
          : "npm install --no-audit --no-fund";
    guard("npm", install);
  }
  if (has("pyproject.toml") && has("poetry.lock")) {
    copy("pyproject.toml", "poetry.lock");
    guard("poetry", "poetry config virtualenvs.in-project true --local && poetry install --no-root --no-interaction");
  } else if (has("requirements.txt")) {
    copy("requirements.txt");
    guard("python3", "python3 -m venv .venv && .venv/bin/pip install -r requirements.txt");
  }
  if (has("Gemfile")) {
    copy("Gemfile", "Gemfile.lock");
    guard("bundle", "bundle config set --local path vendor/bundle && bundle install");
  }
  if (has("composer.json")) {
    copy("composer.json", "composer.lock");
    guard("composer", "composer install --no-interaction --no-progress");
  }
  if (has("Cargo.toml") && has("Cargo.lock")) {
    copy("Cargo.toml", "Cargo.lock");
    guard("cargo", "mkdir -p .cargo && cargo vendor vendor > .cargo/config.toml");
  }
  if (has("go.mod")) {
    copy("go.mod", "go.sum");
    guard("go", "go mod download"); // populates GOMODCACHE inside the image — no restore needed
  }
  return lines.join("\n");
}

export function cacheDockerfile(scratchDir: string, specImage: string, dirs: string[]): string {
  return `FROM ${specImage}\nUSER root\n\n${dirs.map((d) => installFragment(scratchDir, d)).join("\n\n")}\n`;
}

// Fire-and-forget: build the cache image from the spec image + the scratch manifests.
// `onDone` runs after (success or failure) so the caller can clean its scratch dir.
export function buildDependencyCacheInBackground(key: string, specImage: string, scratchDir: string, dirs: string[], onDone: () => void): void {
  const tag = cacheImageTag(key);
  if (building.has(key) || imageExists(tag) || dirs.length === 0) {
    onDone();
    return;
  }
  building.add(key);
  const ctx = mkdtempSync(join(tmpdir(), "isogate-cache-"));
  try {
    cpSync(scratchDir, ctx, { recursive: true });
    writeFileSync(join(ctx, "Dockerfile"), cacheDockerfile(scratchDir, specImage, dirs));
  } catch (e) {
    rmSync(ctx, { recursive: true, force: true });
    building.delete(key);
    onDone();
    log(`context failed: ${String((e as Error)?.message ?? e)}`);
    return;
  }
  log(`building ${tag} from ${specImage} (${dirs.join(", ")})`);
  const p = spawn("docker", ["build", "-t", tag, ctx], { stdio: ["ignore", "ignore", "pipe"] });
  let tail = "";
  p.stderr.on("data", (b: Buffer) => (tail = (tail + b.toString()).slice(-600)));
  p.on("exit", (code) => {
    rmSync(ctx, { recursive: true, force: true });
    building.delete(key);
    if (code === 0) log(`ready: ${tag}`);
    else log(`build failed (${code}): ${tail.trim().split("\n").slice(-3).join(" / ")}`);
    onDone();
  });
  p.on("error", () => {
    rmSync(ctx, { recursive: true, force: true });
    building.delete(key);
    onDone();
  });
}
