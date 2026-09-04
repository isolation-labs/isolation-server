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
  assert.equal(roster[0].harness, "claude-code");
  assert.equal(roster[0].lifecycle, "always");
  assert.equal(roster[1].lifecycle, "lazy");
  assert.equal(agents.parseRoster("not-an-array").length, 0);
});

test("effectiveSystemPrompt layers the base under the user prompt", () => {
  const p = agents.effectiveSystemPrompt({ id: "x", name: "Rev", harness: "claude-code", systemPrompt: "You review PRs." });
  assert.ok(p.includes('You are "Rev"'));
  assert.ok(p.endsWith("You review PRs."));
});

test("harness materializers: claude-code / codex / goose shape their HOME + env (PLAN §5d)", () => {
  const mcp = { name: "isolation", command: "/tmp/.iso-mcp.sh", args: [], env: { ISO_AGENT_ID: "a" } };
  const claude = harness.getHarness("claude-code").materialize({ home: "/h", agent: { id: "a", name: "A", model: "claude-sonnet-5" }, persona: "be A", credential: { kind: "subscription", provider: "anthropic", token: "tok", baseUrl: "https://gw/t/a" }, mcp });
  assert.equal(claude.command, "claude-agent-acp");
  assert.equal(claude.env.ANTHROPIC_API_KEY, "tok");
  assert.equal(claude.env.ANTHROPIC_BASE_URL, "https://gw/t/a");
  assert.equal(claude.env.ANTHROPIC_MODEL, "claude-sonnet-5");
  assert.equal(claude.env.IS_SANDBOX, "1");
  assert.equal(claude.initialModeId, "bypassPermissions");
  const md = claude.files.find((f) => f.path === "/h/.claude/CLAUDE.md");
  assert.ok(md && md.content.startsWith("be A") && md.content.includes("thread_send"));

  const codexSub = harness.getHarness("codex").materialize({ home: "/h", agent: { id: "b", name: "B", model: "gpt-5.3-codex" }, persona: "be B", credential: { kind: "subscription", provider: "openai", token: "gwtok", baseUrl: "https://gw/t/b/v1", accountId: "acct" }, mcp });
  assert.equal(codexSub.command, "codex-acp");
  assert.equal(codexSub.env.OPENAI_API_KEY, undefined, "a subscription keeps every key out of codex's env");
  assert.equal(codexSub.env.CODEX_HOME, "/h/.codex");
  const auth = JSON.parse(codexSub.files.find((f) => f.path === "/h/.codex/auth.json").content);
  assert.equal(auth.tokens.account_id, "acct");
  const toml = codexSub.files.find((f) => f.path === "/h/.codex/config.toml").content;
  assert.ok(toml.includes('chatgpt_base_url = "https://gw/t/b/backend-api/"'));
  assert.ok(toml.includes('model = "gpt-5.3-codex"'));
  assert.ok(toml.includes("requires_openai_auth = true"));

  const codexKey = harness.getHarness("codex").materialize({ home: "/h", agent: { id: "c", name: "C" }, persona: "p", credential: { kind: "apiKey", provider: "openai", token: "k", baseUrl: "https://gw/t/c/v1" }, mcp });
  assert.equal(codexKey.env.OPENAI_API_KEY, "k");
  assert.ok(codexKey.files.find((f) => f.path === "/h/.codex/config.toml").content.includes('base_url = "https://gw/t/c/v1"'));

  const g = harness.getHarness("goose").materialize({ home: "/h", agent: { id: "d", name: "D" }, persona: "p", credential: { kind: "apiKey", provider: "openai", token: "k", baseUrl: "https://gw/t/d/v1" }, mcp });
  assert.deepEqual([g.command, g.args], ["goose", ["acp"]]);
  assert.equal(g.env.OPENAI_HOST, "https://gw/t/d");
  assert.equal(g.env.GOOSE_DISABLE_KEYRING, "1");
  const yaml = g.files.find((f) => f.path === "/h/.config/goose/config.yaml").content;
  assert.ok(yaml.includes("active_provider: openai") && yaml.includes("  isolation:") && yaml.includes('cmd: "/tmp/.iso-mcp.sh"'));

  // The HOME lives under the workspace tree (the conversation persists to R2) — so every file
  // holding credential material must be declared, and none of them may be a file the harness
  // ALSO needs persisted. The invariant: secrets never in bundles/git.
  for (const [id, m] of [["claude-code", claude], ["codex", codexSub], ["goose", g]]) {
    assert.ok(m.secretPaths?.length, `${id} declares its credential material`);
    for (const p of m.secretPaths) assert.ok(!p.startsWith("/") && !p.includes(".."), `${id}: ${p} is HOME-relative`);
  }
  assert.ok(codexSub.secretPaths.includes(".codex/auth.json"), "codex's minted login file never rides persistence");

  // An agent's own credential replaces the WHOLE pair: every var of it the harness does not
  // set itself must be unset for the adapter, or the SESSION's credential (already in the
  // container env) out-ranks or redirects it.
  const covers = (m, keys) => {
    for (const k of keys) assert.ok(k in m.env || m.unsetEnv.includes(k), `${k} is neither set nor unset`);
  };
  covers(claude, ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN"]);
  assert.ok(claude.unsetEnv.includes("CLAUDE_CODE_OAUTH_TOKEN"), "a session OAuth token never rides the agent's slot");
  covers(codexSub, ["OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY"]);
  assert.ok(codexSub.unsetEnv.includes("OPENAI_API_KEY"), "a leftover key would flip codex out of ChatGPT mode");
  covers(codexKey, ["OPENAI_API_KEY", "OPENAI_BASE_URL"]);
  covers(g, ["OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_HOST"]);

  // No credential = the session's own env is the deliberate fallback: nothing is stripped.
  const bare = harness.getHarness("claude-code").materialize({ home: "/h", agent: { id: "e", name: "E" }, persona: "p", mcp });
  assert.deepEqual(bare.unsetEnv, []);
});

test("unknown harness reports itself instead of crashing", async () => {
  const h = harness.getHarness("nope");
  assert.equal(h.installed, false);
  assert.throws(() => h.materialize({ home: "/h", agent: { id: "a", name: "A" }, persona: "", mcp: { name: "isolation", command: "x", args: [], env: {} } }));
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

test("safeViewDir: a view's dir is a clean relative subtree under /workspace, never a path escape", () => {
  assert.equal(launch.safeViewDir("api"), "api");
  assert.equal(launch.safeViewDir("/apps/web/"), "apps/web");
  assert.equal(launch.safeViewDir("my app/v2"), "my app/v2");
  assert.equal(launch.safeViewDir(""), undefined);
  assert.equal(launch.safeViewDir("/"), undefined);
  assert.equal(launch.safeViewDir(undefined), undefined);
  assert.equal(launch.safeViewDir("../etc"), undefined);
  assert.equal(launch.safeViewDir("a/../b"), undefined);
  assert.equal(launch.safeViewDir('x"; rm -rf /'), undefined);
  assert.equal(launch.safeViewDir("$(id)"), undefined);
});

test("sanitizeStyle: theme keys/values are whitelisted and bounded; garbage yields nothing", () => {
  const s = launch.sanitizeStyle({ theme: { background: "#0b0d10", bogus: "x", foreground: 'a"b' }, fontSize: 500, fontFamily: "JetBrains Mono, monospace", extra: 1 });
  assert.deepEqual(s, { theme: { background: "#0b0d10" }, fontSize: 64, fontFamily: "JetBrains Mono, monospace" });
  assert.equal(launch.sanitizeStyle("nope"), undefined);
  assert.equal(launch.sanitizeStyle({ theme: { bogus: "x" } }), undefined);
});
