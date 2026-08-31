// Bundles the first-party code view (web/editor) into dist/editor: main.js/main.css
// (Monaco + our chrome), editor.worker.js (Monaco's base worker), codicon.ttf and
// index.html. Runs as part of `npm run build`, so the assets ship inside the npm
// tarball — the doorman serves them; nothing is fetched at runtime.
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", "editor");
mkdirSync(out, { recursive: true });

// A slim Monaco entry, derived from the shipped editor.main.js: everything EXCEPT the
// worker-backed language services (css/html/json/typescript "features") and the LSP
// client. Monarch syntax highlighting stays. In a one-file-at-a-time sandbox editor
// those services are wrong twice over: they need dedicated workers we'd have to ship
// (the base worker throwing "Missing requestHandler: provideInlayHints" broke opening
// TS files), and a projectless TS service flags every cross-file import as an error.
// Generated as a SIBLING of editor.main.js so its relative imports resolve unchanged.
const monacoEditorDir = join(root, "node_modules/monaco-editor/esm/vs/editor");
const slim = readFileSync(join(monacoEditorDir, "editor.main.js"), "utf8")
  .split("\n")
  .filter((l) => !/monaco-lsp-client|languages\/features|__src_languages_features|\bas lsp\b/.test(l))
  .join("\n");
const slimEntry = join(monacoEditorDir, "editor.slim.main.js");
writeFileSync(slimEntry, slim);

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
