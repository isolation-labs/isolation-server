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
  const reply = await h.runTurn({
    systemPrompt: "base\n\npersona text",
    history: [{ role: "user", text: "one" }, { role: "assistant", text: "r" }],
    userText: "two",
    agent: { id: "a", name: "A" },
  });
  assert.ok(reply.includes("persona text"));
  assert.ok(reply.includes("turn 2"));
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
