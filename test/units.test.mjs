// Unit tests over the built output (dist/) — zero test dependencies, node:test only.
// `npm test` builds first, so these always exercise what ships.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate every module-level store the modules mint on import.
process.env.ISOLATION_SERVER_HOME = mkdtempSync(join(tmpdir(), "iso-test-"));
process.on("exit", () => rmSync(process.env.ISOLATION_SERVER_HOME, { recursive: true, force: true }));

const views = await import("../dist/views.js");
const agents = await import("../dist/agents.js");
const harness = await import("../dist/harness.js");
const localsink = await import("../dist/localsink.js");
const launch = await import("../dist/launch.js");

test("view tokens: mint → verify roundtrip; tampering and expiry fail", () => {
  const v = views.addView("sb-1", "terminal", 7000, {});
  const token = views.mintViewToken(v.id);
  assert.equal(views.verifyViewToken(token, v.id), true);
  assert.equal(views.verifyViewToken(token.slice(0, -2) + "xx", v.id), false); // bad mac
  const [body] = token.split(".");
  assert.equal(views.verifyViewToken(`${body}.deadbeef`, v.id), false);
  assert.equal(views.verifyViewToken(token, "v-other"), false); // scoped to ONE view
});

test("parseAiCred/aiCredEnv: both credential shapes materialize the right env; garbage is refused", () => {
  // The gateway pair — the common case: a scoped isogw_ token + our metering base URL.
  const gw = launch.parseAiCred({ auth: "apiKey", apiKey: "isogw_abc", baseUrl: "https://cloud.example/anthropic" });
  assert.deepEqual(launch.aiCredEnv(gw), { ANTHROPIC_API_KEY: "isogw_abc", ANTHROPIC_BASE_URL: "https://cloud.example/anthropic" });
  // A direct key with no base URL sets only the key.
  assert.deepEqual(launch.aiCredEnv(launch.parseAiCred({ auth: "apiKey", apiKey: "sk-x" })), { ANTHROPIC_API_KEY: "sk-x" });
  // Subscription OAuth → the raw-injection exception, one env var.
  assert.deepEqual(launch.aiCredEnv(launch.parseAiCred({ auth: "subscription", oauthToken: "oat-1" })), { CLAUDE_CODE_OAUTH_TOKEN: "oat-1" });
  // Wrong or missing pieces parse to nothing rather than a half-credential.
  assert.equal(launch.parseAiCred({ auth: "apiKey" }), undefined);
  assert.equal(launch.parseAiCred({ auth: "subscription", apiKey: "sk-x" }), undefined);
  assert.equal(launch.parseAiCred("not-an-object"), undefined);
  assert.equal(launch.parseAiCred(undefined), undefined);
});

test("applyAiCred replaces the whole pair — no leftover env var out-ranks or redirects it", () => {
  // A user's own key + endpoint in the environment config must not survive alongside the
  // session's subscription token (Claude Code would prefer the key, and the stale base URL
  // would send the token to someone else's endpoint).
  const env = { ANTHROPIC_API_KEY: "sk-user", ANTHROPIC_BASE_URL: "https://elsewhere.example", KEEP: "1" };
  launch.applyAiCred(env, { auth: "subscription", oauthToken: "oat-1" });
  assert.deepEqual(env, { CLAUDE_CODE_OAUTH_TOKEN: "oat-1", KEEP: "1" });
  // And the other direction: a gateway pair with no base URL clears a stale one.
  const env2 = { ANTHROPIC_BASE_URL: "https://elsewhere.example", CLAUDE_CODE_OAUTH_TOKEN: "oat-old" };
  launch.applyAiCred(env2, { auth: "apiKey", apiKey: "isogw_abc" });
  assert.deepEqual(env2, { ANTHROPIC_API_KEY: "isogw_abc" });
});

test("web slugs are long enough to be addresses (≥128-bit)", () => {
  const slug = views.newWebSlug();
  assert.match(slug, /^[a-z2-7]{26}$/);
  assert.notEqual(views.newWebSlug(), slug);
});

test("parseRoster: shapes, defaults, and garbage rejection", () => {
  const roster = agents.parseRoster([
    { id: "a", name: "A" },
    { id: "b", name: "B", harness: "claude-code", lifecycle: "lazy", systemPrompt: "review PRs" },
    { name: "no-id" },
    "garbage",
  ]);
  assert.equal(roster.length, 2);
  assert.equal(roster[0].harness, "echo");
  assert.equal(roster[0].lifecycle, "always");
  assert.equal(roster[1].lifecycle, "lazy");
  assert.equal(agents.parseRoster("not-an-array").length, 0);
});

test("effectiveSystemPrompt layers the base under the user prompt", () => {
  const p = agents.effectiveSystemPrompt({ id: "x", name: "Rev", harness: "echo", systemPrompt: "You review PRs." });
  assert.ok(p.includes('You are "Rev"'));
  assert.ok(p.endsWith("You review PRs."));
});

test("echo harness proves persona + per-agent history", async () => {
  const h = harness.getHarness("echo");
  const out = await h.runTurn({
    systemPrompt: "base\n\npersona text",
    history: [{ role: "user", text: "one" }, { role: "assistant", text: "r" }],
    userText: "two",
    agent: { id: "a", name: "A" },
  });
  assert.ok(out.text.includes("persona text"));
  assert.ok(out.text.includes("turn 2"));
});

test("unknown harness reports itself instead of crashing", async () => {
  const h = harness.getHarness("nope");
  assert.equal(h.installed, false);
  await assert.rejects(() => h.runTurn({ systemPrompt: "", history: [], userText: "x", agent: { id: "a", name: "A" } }));
});

test("local sink: ETag CAS contract (create, stale, advance, id safety)", () => {
  assert.equal(localsink.readLocalBlob("wl-t"), undefined);
  const first = localsink.writeLocalBlob("wl-t", Buffer.from("v1"), undefined, true);
  assert.ok(first && first !== "conflict");
  assert.equal(localsink.writeLocalBlob("wl-t", Buffer.from("v2"), undefined, true), "conflict"); // create-only on existing
  assert.equal(localsink.writeLocalBlob("wl-t", Buffer.from("v2"), '"stale"'), "conflict");
  const second = localsink.writeLocalBlob("wl-t", Buffer.from("v2"), first.etag);
  assert.ok(second && second !== "conflict" && second.etag !== first.etag);
  assert.equal(localsink.readLocalBlob("wl-t").bytes.toString(), "v2");
  assert.equal(localsink.writeLocalBlob("../escape", Buffer.from("x")), undefined); // unsafe id
});

test("code view path gate: workspace-relative only, no traversal or control bytes", async () => {
  const { safeRelPath } = await import("../dist/codeview.js");
  assert.equal(safeRelPath("repo/src/index.ts"), "repo/src/index.ts");
  assert.equal(safeRelPath("repo/dir/"), "repo/dir"); // trailing slash normalized
  assert.equal(safeRelPath("a b/wéird name.txt"), "a b/wéird name.txt"); // spaces + unicode fine
  for (const bad of ["", "/etc/passwd", "../secrets", "a/../../b", "a/./b", "a//b", "a\\b", "a\tb", "a\u0000b", null]) {
    assert.equal(safeRelPath(bad), undefined, JSON.stringify(bad));
  }
});

test("code view git: repo + path + branch gates, porcelain parsing", async () => {
  const g = await import("../dist/codegit.js");
  // Repos are NESTED only — the workspace root is the session branch (session sync's).
  assert.equal(g.repoDir("app"), "/workspace/app");
  assert.equal(g.repoDir("packages/api"), "/workspace/packages/api");
  for (const bad of ["", "/", "../x", "a/../b", null]) assert.equal(g.repoDir(bad), undefined, JSON.stringify(bad));
  // Repo-relative paths as git printed them; escapes and newlines (the env-var list separator) refused.
  assert.deepEqual(g.safeRepoPaths("src/a.ts"), ["src/a.ts"]);
  assert.deepEqual(g.safeRepoPaths(["a b.txt", "x$(id).js", "."]), ["a b.txt", "x$(id).js", "."]);
  for (const bad of [[], [""], ["/etc/passwd"], ["a/../b"], ["a\nb"], ["a\u0000b"], [1], "a//b"]) assert.equal(g.safeRepoPaths(bad), undefined, JSON.stringify(bad));
  assert.equal(g.safeBranch("feat/git-in-code-view"), "feat/git-in-code-view");
  for (const bad of ["-x", "a..b", "a b", "a.lock", "a/", "a@{1}", "a:b", "", 3]) assert.equal(g.safeBranch(bad), undefined, JSON.stringify(bad));
  // porcelain v1 -b --ignored: branch/upstream/ahead-behind, XY codes, renames, quoted paths, ignored dirs.
  const st = g.parseStatus("app", [
    "## feat/x...origin/feat/x [ahead 2, behind 1]",
    " M src/a.ts",
    "A  src/new.ts",
    "?? notes.md",
    "R  old.ts -> new.ts",
    'M  "we\\"ird.txt"',
    "!! node_modules/",
    "!! .env",
    "UU conflict.ts",
  ].join("\n"));
  assert.equal(st.branch, "feat/x");
  assert.equal(st.upstream, true);
  assert.deepEqual([st.ahead, st.behind, st.detached], [2, 1, false]);
  assert.deepEqual(st.files.map((f) => [f.index, f.work, f.path, f.renamedFrom]), [
    [" ", "M", "src/a.ts", undefined], ["A", " ", "src/new.ts", undefined], ["?", "?", "notes.md", undefined],
    ["R", " ", "new.ts", "old.ts"], ["M", " ", 'we"ird.txt', undefined], ["U", "U", "conflict.ts", undefined],
  ]);
  assert.deepEqual(st.ignored, ["node_modules/", ".env"]);
  assert.equal(g.parseStatus("d", "## HEAD (no branch)").detached, true);
  assert.equal(g.parseStatus("d", "## No commits yet on main").branch, "main");
  assert.deepEqual([g.parseStatus("d", "## main").branch, g.parseStatus("d", "## main").upstream], ["main", false]);
  assert.equal(g.unquotePath('"caf\\303\\251.txt"'), "café.txt");
});

// --- Credential Vault (PLAN §5b) ---------------------------------------------------

const vault = await import("../dist/vault.js");
const runtime = await import("../dist/runtime.js");

test("parseVaultManifest: keeps well-formed credentials + bindings, drops the rest, refuses empties", () => {
  const m = vault.parseVaultManifest({
    credentials: [
      { name: "gh", value: "isogw_1" },
      { name: "ant", value: "isogw_2" },
      { name: "bad name!", value: "x" }, // invalid name
      { name: "empty", value: "" }, // empty value
      { name: "gh", value: "dup" }, // duplicate
    ],
    bindings: [
      { name: "github", hosts: ["github.com", "*.github.com"], auth: { type: "bearer", credential: "gh" } },
      { name: "anthropic", hosts: ["cloud.example"], paths: ["/anthropic/*"], methods: ["post"], auth: { type: "apiKey", name: "x-api-key", credential: "ant" } },
      { name: "sig", hosts: ["cloud.example"], auth: { type: "customHeaders", headers: [{ name: "X-Iso-Server", credential: "ant" }] } },
      { name: "dangling", hosts: ["h.example"], auth: { type: "bearer", credential: "nope" } }, // unknown credential
      { name: "nohost", hosts: [], auth: { type: "bearer", credential: "gh" } },
      { name: "badauth", hosts: ["h.example"], auth: { type: "passthrough" } },
      { name: "badhost", hosts: ["not a host"], auth: { type: "bearer", credential: "gh" } },
      { name: "dotless", hosts: ["localhost"], auth: { type: "bearer", credential: "gh" } }, // the sidecar wants an FQDN
    ],
    env: { ANTHROPIC_BASE_URL: "https://cloud.example/anthropic", N: 5 },
  });
  assert.deepEqual(m.credentials.map((c) => c.name), ["gh", "ant"]);
  assert.deepEqual(m.bindings.map((b) => b.name), ["github", "anthropic", "sig"]);
  assert.deepEqual(m.bindings[1].methods, ["POST"]);
  assert.deepEqual(m.env, { ANTHROPIC_BASE_URL: "https://cloud.example/anthropic" });
  // No usable binding (or credential) → no vault at all, never a half one.
  assert.equal(vault.parseVaultManifest({ credentials: [{ name: "a", value: "v" }], bindings: [] }), undefined);
  assert.equal(vault.parseVaultManifest({ credentials: [], bindings: [{ name: "b", hosts: ["h.example"], auth: { type: "bearer", credential: "a" } }] }), undefined);
  assert.equal(vault.parseVaultManifest("sealed-but-undecryptable"), undefined);
  assert.equal(vault.parseVaultManifest(undefined), undefined);
});

test("cloneTarget: a rewritten repo clones from the gateway remote with its scoped token; others untouched", () => {
  const basic = Buffer.from("x-access-token:isogw_git").toString("base64");
  const m = vault.parseVaultManifest({
    credentials: [{ name: "git-1", value: basic }],
    bindings: [{ name: "git-1", hosts: ["app.example"], paths: ["/git/github.com/o/b/*", "/git/github.com/o/b.git/*"], auth: { type: "basic", credential: "git-1" } }],
    rewrites: { "https://github.com/o/b.git": "https://app.example/git/github.com/o/b", "ftp://bad": "nope", "https://x": "not-a-url" },
  });
  assert.deepEqual(m.rewrites, { "https://github.com/o/b.git": "https://app.example/git/github.com/o/b" });
  assert.deepEqual(vault.cloneTarget(m, "https://github.com/o/b.git"), { url: "https://app.example/git/github.com/o/b", token: "isogw_git" });
  assert.deepEqual(vault.cloneTarget(m, "https://github.com/o/b"), { url: "https://app.example/git/github.com/o/b", token: "isogw_git" });
  assert.deepEqual(vault.cloneTarget(m, "https://github.com/o/a"), { url: "https://github.com/o/a" });
  assert.deepEqual(vault.cloneTarget(undefined, "https://github.com/o/a"), { url: "https://github.com/o/a" });
  assert.equal(vault.vaultCoversHost(m, "https://app.example/git/github.com/o/b"), true);
  // Only `basic` values are base64("user:token") — any other scheme holds the token verbatim
  // and must never be "decoded" (Buffer.from(…, "base64") silently yields garbage instead).
  const bearer = vault.parseVaultManifest({
    credentials: [{ name: "g", value: "isogw_raw" }],
    bindings: [{ name: "g", hosts: ["app.example"], auth: { type: "bearer", credential: "g" } }],
    rewrites: { "https://github.com/o/b": "https://app.example/git/github.com/o/b" },
  });
  assert.deepEqual(vault.cloneTarget(bearer, "https://github.com/o/b"), { url: "https://app.example/git/github.com/o/b", token: "isogw_raw" });
});

test("vaultCoversHost: exact + wildcard hosts decide whether a clone needs its own token", () => {
  const m = vault.parseVaultManifest({
    credentials: [{ name: "gh", value: "t" }],
    bindings: [{ name: "gh", hosts: ["github.com", "*.gitlab.example"], auth: { type: "bearer", credential: "gh" } }],
  });
  assert.equal(vault.vaultCoversHost(m, "https://github.com/o/r.git"), true);
  assert.equal(vault.vaultCoversHost(m, "https://GitHub.com/o/r"), true);
  assert.equal(vault.vaultCoversHost(m, "https://code.gitlab.example/o/r"), true);
  assert.equal(vault.vaultCoversHost(m, "https://gitlab.example/o/r"), true);
  assert.equal(vault.vaultCoversHost(m, "https://bitbucket.org/o/r"), false);
  assert.equal(vault.vaultCoversHost(m, "git@github.com:o/r.git"), false); // not a URL → no
  assert.equal(vault.vaultCoversHost(undefined, "https://github.com/o/r"), false);
});

test("ensureEgressConfig: upgrades dns→dns+nft, adds a missing section/image, leaves a tuned config alone", () => {
  const base = `[server]\nhost = "127.0.0.1"\n\n[runtime]\ntype = "docker"\n`;
  // Missing section → appended whole.
  const a = runtime.ensureEgressConfig(base);
  assert.equal(a.changed, true);
  assert.match(a.toml, /\[egress\]\nimage = "opensandbox\/egress:v[\d.]+"\nmode = "dns\+nft"\n$/);
  // The shipped example: dns → dns+nft, image kept as the operator has it.
  const b = runtime.ensureEgressConfig(`${base}\n[egress]\nimage = "opensandbox/egress:v9.9.9"\nmode = "dns"\n\n[renew_intent]\nenabled = false\n`);
  assert.equal(b.changed, true);
  assert.match(b.toml, /\[egress\]\nimage = "opensandbox\/egress:v9.9.9"\nmode = "dns\+nft"\n\n\[renew_intent\]/);
  // Already right → untouched, byte for byte.
  const c = runtime.ensureEgressConfig(b.toml);
  assert.equal(c.changed, false);
  assert.equal(c.toml, b.toml);
  // Section with no image/mode lines → both added.
  const d = runtime.ensureEgressConfig(`${base}\n[egress]\nreadiness_timeout_seconds = 30.0\n`);
  assert.equal(d.changed, true);
  assert.match(d.toml, /\[egress\]\nimage = "opensandbox\/egress:v[\d.]+"\nmode = "dns\+nft"\nreadiness_timeout_seconds = 30.0\n/);
});
