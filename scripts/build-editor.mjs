// Bundles the first-party code view (web/editor) into dist/editor: main.js/main.css
// (Monaco + our chrome), editor.worker.js (Monaco's base worker), codicon.ttf and
// index.html. Runs as part of `npm run build`, so the assets ship inside the npm
// tarball — the doorman serves them; nothing is fetched at runtime.
import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", "editor");
mkdirSync(out, { recursive: true });

await build({
  entryPoints: [join(root, "web/editor/main.ts")],
  bundle: true,
  minify: true,
  format: "esm",
  outdir: out,
  loader: { ".ttf": "file" },
  assetNames: "[name]", // stable codicon.ttf — the doorman serves the flat directory
  logLevel: "warning",
});

// The worker must be its own classic-script bundle (Monaco spawns it by URL).
await build({
  entryPoints: [join(root, "node_modules/monaco-editor/esm/vs/editor/editor.worker.js")],
  bundle: true,
  minify: true,
  format: "iife",
  outfile: join(out, "editor.worker.js"),
  logLevel: "warning",
});

copyFileSync(join(root, "web/editor/index.html"), join(out, "index.html"));
console.log("[build-editor] dist/editor ready");
