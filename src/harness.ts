// The harness abstraction (PLAN §5d — every harness is an ACP agent). An agent names a harness;
// the harness MATERIALIZES the agent into a sandbox: the files under the agent's own HOME (its
// instructions, its credential files, its config), the command that starts the ACP adapter,
// and the env it runs with. The in-sandbox bridge (sandbox/iso-acp-bridge.mjs) then drives the
// adapter over ACP — one identical client for claude-code, codex and goose; the harness-specific
// knowledge lives entirely here. An unknown/uninstalled harness reports itself rather than
// vanishing — the same "(not installed)" honesty as the catalog.
import type { AgentCredential } from "./agents.js";

export type HarnessId = string;

export interface MaterializeInput {
  home: string; // the agent's HOME inside the sandbox (per agent, under the workspace tree)
  agent: { id: string; name: string; model?: string };
  persona: string; // the base Isolation prompt + the user's instructions, already merged
  credential?: AgentCredential; // the agent's own credential (its gateway slot), else none
  mcp: { name: string; command: string; args: string[]; env: Record<string, string> }; // the isolation MCP server
}

export interface Materialized {
  command: string;
  args: string[];
  env: Record<string, string>;
  // Env names the adapter must NOT inherit from the container (see `unsetFor` below). The
  // bridge deletes these from the inherited environment before applying `env`.
  unsetEnv?: string[];
  files: { path: string; content: string; mode?: number }[];
  initialModeId?: string; // an ACP session mode to select right after session/new, when offered
  // HOME-relative paths holding CREDENTIAL material — ours or the harness's own (it may write
  // its login file at runtime). The agent's HOME lives under the workspace tree so the
  // conversation persists, and that tree is committed + bundled to R2: these must never ride
  // it (the invariant — secrets never in bundles/git). acpview.ts turns them into a
  // `.gitignore` inside the HOME before any of them can exist.
  secretPaths?: string[];
}

export interface Harness {
  id: HarnessId;
  label: string;
  installed: boolean;
  materialize(input: MaterializeInput): Materialized;
}

export const shq = (v: string): string => `'${v.replace(/'/g, `'\\''`)}'`;

// --- shared pieces ------------------------------------------------------------------

// The instructions file every harness reads at start. The persona is the user's layer; the
// framework layer names the `isolation` tools so the agent knows they exist.
const instructions = (persona: string): string =>
  [
    persona,
    "",
    "## Isolation",
    "You run inside an Isolation session. The `isolation` MCP server gives you tools: `session_info` (who/where you are),",
    "`views` (the windows of this session), `memory_read`/`memory_write` (your own note for this workspace — keep it short and",
    "current), and `thread_send` (message another agent's thread). Read your memory when a task touches earlier work.",
    "",
  ].join("\n");

const envList = (env: Record<string, string>): { name: string; value: string }[] => Object.entries(env).map(([name, value]) => ({ name, value }));

// The container's env already carries the SESSION's credential (launch.ts applyAiCred + the
// vault's routing env). An agent with its OWN credential replaces the WHOLE pair, exactly as
// applyAiCred does host-side: every var of the pair the harness does not set itself must be
// UNSET for the adapter, or a leftover out-ranks or redirects it. Hard-learned: a leftover
// CLAUDE_CODE_OAUTH_TOKEN wins over the agent's ANTHROPIC_API_KEY while the agent's
// ANTHROPIC_BASE_URL still applies — the session's raw OAuth token, shipped to the agent's
// gateway slot; a leftover OPENAI_API_KEY flips codex out of ChatGPT mode and straight to
// api.openai.com, past the gateway entirely. Partial application is worse than none.
const ANTHROPIC_ENV = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN"];
const OPENAI_ENV = ["OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_HOST", "OPENAI_BASE_PATH", "CODEX_API_KEY", "CODEX_SUBSCRIPTION", "CODEX_ACCOUNT_ID", "CODEX_HOME"];
const unsetFor = (keys: string[], set: Record<string, string>): string[] => keys.filter((k) => !(k in set));

// --- Codex login/config (a ChatGPT subscription through the gateway) --------------------

// Codex's login file for a ChatGPT subscription: the (gateway) token as the access token — the
// gateway resolves the real OAuth — plus the account id the backend keys the plan off.
// Codex decides "logged in" by DECODING the id token's claims (it cannot verify a signature and
// does not try): a locally minted JWT with the account id is enough. The access token is the
// gateway token — the gateway swaps in the real OAuth Bearer.
const b64u = (v: string): string => Buffer.from(v, "utf8").toString("base64url");
export const codexIdToken = (accountId: string): string => {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: "isolation", sub: accountId, exp: now + 365 * 86400, iat: now, email: "", "https://api.openai.com/auth": { chatgpt_account_id: accountId, chatgpt_plan_type: "pro", chatgpt_user_id: accountId } };
  return `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}.${b64u("isolation")}`;
};
// The access token must ALSO decode as a JWT (codex reads `exp` from it; an opaque token makes it
// "refresh" with the empty refresh token and fail) — so the gateway token rides inside one, as the
// `isogw` claim; the gateway unwraps it.
export const codexAccessToken = (gatewayToken: string, accountId: string): string => {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: "isolation", sub: accountId, exp: now + 365 * 86400, iat: now, isogw: gatewayToken, "https://api.openai.com/auth": { chatgpt_account_id: accountId, chatgpt_plan_type: "pro" } };
  return `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}.${b64u("isolation")}`;
};
export const codexAuthJson = (accessToken: string, accountId: string): string =>
  JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: codexIdToken(accountId), access_token: codexAccessToken(accessToken, accountId), refresh_token: "", account_id: accountId }, last_refresh: new Date().toISOString() });
export const codexLoginFile = (accessToken: string, accountId: string): string => `mkdir -p ~/.codex && printf '%s' ${shq(codexAuthJson(accessToken, accountId))} > ~/.codex/auth.json && chmod 600 ~/.codex/auth.json`;

// Codex's config for a gateway slot. ChatGPT mode through the gateway: codex's built-in provider
// speaks a websocket the gateway cannot carry, so the slot is declared as a provider of our own in
// ChatGPT-auth mode (requires_openai_auth) with websockets off — plain HTTPS to
// <slot>/backend-api/codex. An API key rides an explicit HTTP-only provider (the default dials
// api.openai.com over a websocket, ignoring OPENAI_BASE_URL).
export function codexConfigToml(opts: { gatewayRoot?: string; subscription: boolean; model?: string }): string {
  const lines: string[] = [];
  if (opts.model) lines.push(`model = ${JSON.stringify(opts.model)}`);
  if (opts.gatewayRoot && opts.subscription) {
    lines.push(`chatgpt_base_url = ${JSON.stringify(`${opts.gatewayRoot}/backend-api/`)}`, `preferred_auth_method = "chatgpt"`, `model_provider = "iso"`, "", "[model_providers.iso]", `name = "iso"`, `base_url = ${JSON.stringify(`${opts.gatewayRoot}/backend-api/codex`)}`, `wire_api = "responses"`, `supports_websockets = false`, `requires_openai_auth = true`);
  } else if (opts.gatewayRoot) {
    lines.push(`model_provider = "iso"`, "", "[model_providers.iso]", `name = "iso"`, `base_url = ${JSON.stringify(`${opts.gatewayRoot}/v1`)}`, `wire_api = "responses"`, `supports_websockets = false`, `env_key = "OPENAI_API_KEY"`);
  }
  return `${lines.join("\n")}\n`;
}

// --- the harnesses -----------------------------------------------------------------

// Claude Code through the official ACP adapter. Its instructions live in the agent's own
// user-level CLAUDE.md; permissions default to bypass (the sandbox IS the boundary — the
// adapter only allows that with IS_SANDBOX set); the credential is the agent's gateway slot.
const claudeCode: Harness = {
  id: "claude-code",
  label: "Claude Code (ACP)",
  installed: true,
  materialize({ home, agent, persona, credential, mcp }) {
    const env: Record<string, string> = { IS_SANDBOX: "1", NO_BROWSER: "1", ...(agent.model ? { ANTHROPIC_MODEL: agent.model } : {}) };
    if (credential) {
      env.ANTHROPIC_API_KEY = credential.token;
      if (credential.baseUrl) env.ANTHROPIC_BASE_URL = credential.baseUrl;
    }
    void mcp; // registered through ACP's session/new (the bridge config), not a file
    return {
      command: "claude-agent-acp",
      args: [],
      env,
      unsetEnv: credential ? unsetFor(ANTHROPIC_ENV, env) : [],
      files: [
        { path: `${home}/.claude/CLAUDE.md`, content: instructions(persona), mode: 0o600 },
        { path: `${home}/.claude/settings.json`, content: JSON.stringify({ permissions: { defaultMode: "bypassPermissions" } }, null, 2), mode: 0o600 },
        // Skip the CLI's first-run onboarding (theme/login prompts) in an unattended home.
        { path: `${home}/.claude.json`, content: JSON.stringify({ hasCompletedOnboarding: true, theme: "dark" }), mode: 0o600 },
      ],
      initialModeId: "bypassPermissions",
      // The credential rides env here, but the CLI writes its own login file if it ever logs in.
      secretPaths: [".claude/.credentials.json"],
    };
  },
};

// Codex through the official ACP adapter: the login + config files in the agent's own
// ~/.codex (a ChatGPT subscription is a minted JWT pair pointing at the gateway slot; an API
// key is an HTTP-only provider at the slot), instructions in ~/.codex/AGENTS.md, approvals and
// codex's own sandbox bypassed — ours is the boundary.
const codex: Harness = {
  id: "codex",
  label: "Codex (ACP)",
  installed: true,
  materialize({ home, agent, persona, credential, mcp }) {
    void mcp;
    const sub = credential?.kind === "subscription";
    const gatewayRoot = credential?.baseUrl?.replace(/\/+$/, "").replace(/\/v1$/, "");
    const env: Record<string, string> = { NO_BROWSER: "1", INITIAL_AGENT_MODE: "agent-full-access", CODEX_HOME: `${home}/.codex` };
    const files: Materialized["files"] = [
      { path: `${home}/.codex/AGENTS.md`, content: instructions(persona), mode: 0o600 },
      { path: `${home}/.codex/config.toml`, content: codexConfigToml({ gatewayRoot, subscription: sub, model: agent.model }), mode: 0o600 },
    ];
    if (credential && sub) {
      // In ChatGPT mode an API key in the environment wins over the login file and flips codex to
      // API-key mode — keep every key out of its env; the login file carries the gateway token.
      files.push({ path: `${home}/.codex/auth.json`, content: codexAuthJson(credential.token, credential.accountId ?? ""), mode: 0o600 });
    } else if (credential) {
      env.OPENAI_API_KEY = credential.token;
      env.CODEX_API_KEY = credential.token;
    }
    return { command: "codex-acp", args: [], env, unsetEnv: credential ? unsetFor(OPENAI_ENV, env) : [], files, secretPaths: [".codex/auth.json"] };
  },
};

// goose (native ACP): every other provider's API key. Its provider config points at the
// agent's gateway slot (OpenAI-shaped — the gateway resolves the real upstream), secrets come
// from env (no keyring in a container), the `isolation` MCP server is a stdio extension, and
// approvals are off (GOOSE_MODE auto) — the sandbox is the boundary.
const goose: Harness = {
  id: "goose",
  label: "goose (ACP)",
  installed: true,
  materialize({ home, agent, persona, credential, mcp }) {
    const host = credential?.baseUrl?.replace(/\/+$/, "").replace(/\/v1$/, "");
    const model = agent.model || "gpt-5.1";
    const env: Record<string, string> = { GOOSE_DISABLE_KEYRING: "1", GOOSE_MODE: "auto", GOOSE_PROVIDER: "openai", GOOSE_MODEL: model, NO_BROWSER: "1" };
    if (credential) {
      env.OPENAI_API_KEY = credential.token;
      if (host) env.OPENAI_HOST = host;
    }
    const yaml = [
      "active_provider: openai",
      "providers:",
      "  openai:",
      "    enabled: true",
      "    configured: true",
      `    model: ${JSON.stringify(model)}`,
      "GOOSE_PROVIDER: openai",
      `GOOSE_MODEL: ${JSON.stringify(model)}`,
      "GOOSE_MODE: auto",
      "extensions:",
      "  developer:",
      "    type: builtin",
      "    name: developer",
      "    display_name: Developer",
      "    enabled: true",
      "    bundled: true",
      "    timeout: 300",
      `  ${mcp.name}:`,
      "    type: stdio",
      `    name: ${mcp.name}`,
      `    display_name: ${mcp.name}`,
      "    enabled: true",
      `    cmd: ${JSON.stringify(mcp.command)}`,
      `    args: ${JSON.stringify(mcp.args)}`,
      `    envs: ${JSON.stringify(mcp.env)}`,
      "    env_keys: []",
      "    timeout: 300",
      "",
    ].join("\n");
    return {
      command: "goose",
      args: ["acp"],
      env,
      unsetEnv: credential ? unsetFor(OPENAI_ENV, env) : [],
      files: [
        { path: `${home}/.config/goose/config.yaml`, content: yaml, mode: 0o600 },
        { path: `${home}/.config/goose/.goosehints`, content: instructions(persona), mode: 0o600 },
      ],
      // No keyring in a container: goose spills whatever it is asked to remember here.
      secretPaths: [".config/goose/secrets.yaml"],
    };
  },
};

const registry = new Map<HarnessId, Harness>([
  [claudeCode.id, claudeCode],
  [codex.id, codex],
  [goose.id, goose],
]);

export function registerHarness(h: Harness): void {
  registry.set(h.id, h);
}

// Resolve a harness; an unknown id degrades to one that reports itself unavailable, so a view
// shows a clear message instead of a dead bridge.
export function getHarness(id: HarnessId): Harness {
  return (
    registry.get(id) ?? {
      id,
      label: `${id} (not installed)`,
      installed: false,
      materialize() {
        throw new Error(`harness "${id}" is not available in this session`);
      },
    }
  );
}

export const listHarnesses = (): { id: HarnessId; label: string; installed: boolean }[] => [...registry.values()].map((h) => ({ id: h.id, label: h.label, installed: h.installed }));

// `envList` is what ACP's McpServerStdio wants for env.
export { envList as mcpEnvList };
