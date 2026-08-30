// Content hashes that key the image caches (PLAN O4). The WORKSPACE hash decides
// whether analysis + the spec image must be rebuilt; the DEPENDENCY hash keys the
// (later) dependency-cache image. Both hash the contents of a fixed set of files under
// the host-side detection fetch, so they're stable across machines.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// Files whose contents determine HOW to launch — a change re-runs analysis.
export const WS_HASH_FILES = ["Dockerfile", "docker-compose.yml", "compose.yml", "package.json", "pyproject.toml", "Cargo.toml", "go.mod", "Gemfile", "composer.json"];
// Files whose contents determine the dependency set.
export const DEP_HASH_FILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "requirements.txt", "go.sum", "Gemfile.lock", "composer.lock"];
// Everything worth fetching host-side for analysis (turned into sparse-checkout patterns).
export const DETECTION_GLOBS = [".devcontainer", ".devcontainer.json", ...WS_HASH_FILES, ...DEP_HASH_FILES];

// Version of the tooling layer (images.ts Dockerfile template + the in-sandbox
// forwarder). Folded into the workspace hash so a tooling change rebuilds spec images
// instead of silently reusing stale ones. BUMP on any change to the template.
//   1 — first isogate tooling layer: git/tmux/ttyd/code-server/filebrowser + iso-node.
export const TOOLING_VERSION = "1";

const SKIP_DIRS = new Set(["node_modules", ".git"]);

function collect(root: string, pick: (rel: string, base: string) => boolean): [string, string][] {
  const out: [string, string][] = [];
  const walk = (dir: string, rel: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      const abs = join(dir, name);
      const relPath = rel ? `${rel}/${name}` : name;
      let s;
      try {
        s = statSync(abs);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        if (SKIP_DIRS.has(name)) continue;
        walk(abs, relPath);
      } else if (pick(relPath, name)) out.push([relPath, abs]);
    }
  };
  walk(root, "");
  return out;
}

function hashPicked(root: string, pick: (rel: string, base: string) => boolean): string {
  const files = collect(root, pick).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const h = createHash("sha256");
  for (const [rel, abs] of files) {
    h.update(rel).update("\0").update(createHash("sha256").update(readFileSync(abs)).digest("hex")).update("\n");
  }
  return h.digest("hex");
}

const wsPick = (rel: string, base: string) => WS_HASH_FILES.includes(base) || base === ".devcontainer.json" || rel.split("/").includes(".devcontainer");
const depPick = (_rel: string, base: string) => DEP_HASH_FILES.includes(base);

export const workspaceHash = (root: string): string =>
  createHash("sha256").update(TOOLING_VERSION).update("\0").update(hashPicked(root, wsPick)).digest("hex");
export const dependencyHash = (root: string): string => hashPicked(root, depPick);
export const cacheKey = (ws: string, dep: string): string => createHash("sha256").update(ws).update("\0").update(dep).digest("hex");
