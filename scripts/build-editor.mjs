// Bundles the first-party code view (web/editor) into dist/editor: main.js/main.css
// (Monaco + our chrome), editor.worker.js (Monaco's base worker), codicon.ttf and
// index.html. Runs as part of `npm run build`, so the assets ship inside the npm
// tarball — the doorman serves them; nothing is fetched at runtime.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

const hashOf = (file) => createHash("sha256").update(readFileSync(file)).digest("hex").slice(0, 10);

// The worker must be its own classic-script bundle (Monaco spawns it by URL).
await build({
  entryPoints: [join(root, "node_modules/monaco-editor/esm/vs/editor/editor.worker.js")],
  bundle: true,
  minify: true,
  format: "iife",
  outfile: join(out, "editor.worker.js"),
  logLevel: "warning",
});
const workerV = hashOf(join(out, "editor.worker.js"));

await build({
  entryPoints: [join(root, "web/editor/main.ts")],
  bundle: true,
  minify: true,
  format: "esm",
  outdir: out,
  loader: { ".ttf": "file" },
  assetNames: "[name]", // stable codicon.ttf — the doorman serves the flat directory
  // Cache-busting for the worker URL main.js constructs at runtime.
  define: { __WORKER_V__: JSON.stringify(workerV) },
  logLevel: "warning",
});

// Assets are served with an hour of cache; a version query on every reference makes an
// upgraded server take effect on the next page load instead. The doorman ignores the
// query when resolving asset names.
function stampHtml(srcHtml, dir) {
  const html = readFileSync(srcHtml, "utf8")
    .replace("./main.css", `./main.css?v=${hashOf(join(dir, "main.css"))}`)
    .replace("./main.js", `./main.js?v=${hashOf(join(dir, "main.js"))}`);
  writeFileSync(join(dir, "index.html"), html);
}
stampHtml(join(root, "web/editor/index.html"), out);

// The agent view (PLAN §5d): the ACP client page — Preact + zustand over the official SDK,
// same doorman-served pattern.
{
  const appOut = join(root, "dist", "agent");
  mkdirSync(appOut, { recursive: true });
  await build({
    entryPoints: [join(root, "web/agent/main.tsx")],
    bundle: true,
    minify: true,
    format: "esm",
    platform: "browser",
    outdir: appOut,
    entryNames: "main",
    jsx: "automatic",
    jsxImportSource: "preact",
    define: { "process.env.NODE_ENV": '"production"' },
    logLevel: "warning",
  });
  stampHtml(join(root, "web/agent/index.html"), appOut);
}

// The in-sandbox scripts (the ACP bridge + the isolation MCP server) ship verbatim: the server
// writes them into each sandbox at view start.
{
  const out = join(root, "dist", "sandbox");
  mkdirSync(out, { recursive: true });
  for (const f of readdirSync(join(root, "sandbox"))) if (f.endsWith(".mjs")) copyFileSync(join(root, "sandbox", f), join(out, f));
}
console.log("[build-editor] dist/{editor,agent,sandbox} ready");
