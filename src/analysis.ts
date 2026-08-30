// Launch analysis (PLAN O4): decide WHICH IMAGE a workspace runs from.
//   1. fetchDetectionFiles — a host-side blobless, sparse, shallow fetch of only the
//      detection files (kilobytes), so hashes + analysis run before we create the sandbox.
//   2. analyzeLaunch — a repo's own .devcontainer wins; else generate a config from the
//      detected languages. images.ts turns the result into `isogate-spec:<wsHash>`.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LAUNCH_SCRATCH } from "./config.js";
import { DETECTION_GLOBS } from "./hashes.js";

export interface DevContainerConfig {
  image?: string;
  dockerFile?: string;
  build?: { dockerfile?: string; context?: string };
  features?: Record<string, unknown>;
  dockerComposeFile?: string | string[];
  service?: string;
  name?: string;
  raw?: Record<string, unknown>; // the parsed devcontainer.json (lifecycle hooks live here)
}

export interface LaunchSpec {
  source: "repository" | "generated";
  devContainer: DevContainerConfig;
  repoDir?: string; // repository source: the repo whose .devcontainer was used
}

export interface AnalysisRepo {
  url: string;
  dir: string;
  branch?: string;
  token?: string; // transient clone auth (per-repo override or the account default)
}

// Generated-config base images by language — all multi-arch (amd64 + arm64).
const NODE_IMAGE = "mcr.microsoft.com/devcontainers/typescript-node:22";
const PYTHON_IMAGE = "mcr.microsoft.com/devcontainers/python:3.12";
const RUST_IMAGE = "mcr.microsoft.com/devcontainers/rust:1";
const GO_IMAGE = "mcr.microsoft.com/devcontainers/go:1";
const RUBY_IMAGE = "mcr.microsoft.com/devcontainers/ruby:3";
const PHP_IMAGE = "mcr.microsoft.com/devcontainers/php:8";

const sparsePatterns = DETECTION_GLOBS.map((g) => (g === ".devcontainer" ? ".devcontainer/" : g));

function git(args: string[], cwd?: string, env?: NodeJS.ProcessEnv): { ok: boolean; out: string } {
  const r = spawnSync("git", args, { cwd, env: env ?? process.env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return { ok: r.status === 0, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

// Host-side clone with the credential handed to git via GIT_ASKPASS from the env —
// never argv, never the URL, never .git/config.
export function hostClone(url: string, dest: string, token: string | undefined, extra: string[] = []): boolean {
  const askDir = token ? mkdtempSync(join(tmpdir(), "isogate-askpass-")) : "";
  try {
    const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
    if (token) {
      const script = join(askDir, "askpass.sh");
      writeFileSync(script, '#!/bin/sh\ncase "$1" in\n  Username*) printf %s "$ISO_GIT_USER" ;;\n  *) printf %s "$ISO_GIT_TOKEN" ;;\nesac\n', { mode: 0o700 });
      chmodSync(script, 0o700);
      env.GIT_ASKPASS = script;
      env.ISO_GIT_USER = "x-access-token";
      env.ISO_GIT_TOKEN = token;
    }
    return git(["clone", ...extra, url, dest], undefined, env).ok;
  } finally {
    if (askDir) rmSync(askDir, { recursive: true, force: true });
  }
}

const scratchRoot = (id: string) => join(LAUNCH_SCRATCH, id);

export function fetchDetectionFiles(repos: AnalysisRepo[], id: string): string {
  const root = scratchRoot(id);
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  for (const r of repos) {
    if (/^(git@|ssh:\/\/)/.test(r.url)) continue; // v1: SSH repos skip analysis (clone still happens in-sandbox)
    const dir = join(root, r.dir);
    const extra = ["--filter=blob:none", "--no-checkout", "--depth", "1", ...(r.branch ? ["--branch", r.branch] : [])];
    if (!hostClone(r.url, dir, r.token, extra)) continue; // unreachable for analysis → skip, never sink the launch
    git(["sparse-checkout", "init", "--no-cone"], dir);
    git(["sparse-checkout", "set", "--no-cone", ...sparsePatterns], dir);
    git(["checkout"], dir);
  }
  return root;
}

export const cleanScratch = (id: string): void => rmSync(scratchRoot(id), { recursive: true, force: true });

// --- detection ---------------------------------------------------------------

function findFiles(root: string, match: (base: string) => boolean): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      const abs = join(dir, name);
      let s;
      try {
        s = statSync(abs);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        if (name !== "node_modules" && name !== ".git") walk(abs);
      } else if (match(name)) out.push(abs);
    }
  };
  walk(root);
  return out;
}

// devcontainer.json is JSONC (comments + trailing commas) — strip the common cases.
export function parseJsonc(text: string): Record<string, unknown> | undefined {
  const s = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1").replace(/,(\s*[}\]])/g, "$1");
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function devContainerFrom(raw: Record<string, unknown>): DevContainerConfig {
  const build = raw.build as { dockerfile?: string; context?: string } | undefined;
  const features = raw.features as Record<string, unknown> | undefined;
  return {
    image: typeof raw.image === "string" ? raw.image : undefined,
    dockerFile: typeof raw.dockerFile === "string" ? raw.dockerFile : build?.dockerfile,
    build,
    features: features && typeof features === "object" && Object.keys(features).length ? features : undefined,
    dockerComposeFile: (raw.dockerComposeFile as string | string[]) ?? undefined,
    service: typeof raw.service === "string" ? raw.service : undefined,
    name: typeof raw.name === "string" ? raw.name : undefined,
    raw,
  };
}

const PRIMARY: [string, string][] = [["node", NODE_IMAGE], ["python", PYTHON_IMAGE], ["rust", RUST_IMAGE], ["go", GO_IMAGE], ["ruby", RUBY_IMAGE], ["php", PHP_IMAGE]];
const FEATURE: Record<string, string> = {
  node: "ghcr.io/devcontainers/features/node:1",
  python: "ghcr.io/devcontainers/features/python:1",
  rust: "ghcr.io/devcontainers/features/rust:1",
  go: "ghcr.io/devcontainers/features/go:1",
  ruby: "ghcr.io/devcontainers/features/ruby:1",
  php: "ghcr.io/devcontainers/features/php:1",
};

function detectLanguages(root: string): Set<string> {
  const has = (names: string[]) => findFiles(root, (b) => names.includes(b)).length > 0;
  const s = new Set<string>();
  if (has(["package.json"])) s.add("node");
  if (has(["pyproject.toml", "requirements.txt"])) s.add("python");
  if (has(["Cargo.toml"])) s.add("rust");
  if (has(["go.mod"])) s.add("go");
  if (has(["Gemfile"])) s.add("ruby");
  if (has(["composer.json"])) s.add("php");
  return s;
}

// Single language → its base image. Several → a primary base + the others as dev
// container FEATURES (built via `devcontainer build`). node+python → the python image
// (the tooling layer's iso-node provides Node). None → {} (the default base).
function generatedConfig(root: string): DevContainerConfig {
  const langs = detectLanguages(root);
  if (langs.size === 0) return {};
  if (langs.size === 2 && langs.has("node") && langs.has("python")) return { image: PYTHON_IMAGE };
  const primary = PRIMARY.find(([l]) => langs.has(l));
  if (!primary) return {};
  if (langs.size === 1) return { image: primary[1] };
  const features: Record<string, unknown> = {};
  for (const [l] of PRIMARY) if (langs.has(l) && l !== primary[0]) features[FEATURE[l]] = {};
  return { image: primary[1], features };
}

export function analyzeLaunch(scratchDir: string): LaunchSpec {
  for (const f of findFiles(scratchDir, (b) => b === "devcontainer.json" || b === ".devcontainer.json")) {
    const raw = parseJsonc(readFileSync(f, "utf8"));
    if (raw) {
      const repoDir = f.slice(scratchDir.length).replace(/^\/+/, "").split("/")[0];
      return { source: "repository", devContainer: devContainerFrom(raw), repoDir };
    }
  }
  return { source: "generated", devContainer: generatedConfig(scratchDir) };
}
