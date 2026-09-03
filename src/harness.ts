// The harness abstraction (PLAN O5 — agnostic brains). An agent names a harness; the
// supervisor runs a turn through it. One tiny interface keeps the model model-agnostic:
// `echo` is built in (deterministic, zero credentials — the credential-free test + demo
// path); real adapters (claude-code / codex / gemini over ACP, or a CLI in the sandbox)
// implement the SAME interface and register here. An unknown/uninstalled harness reports
// itself rather than vanishing — the same "(not installed)" honesty as the catalog.
import { AI_ENV_KEYS } from "./launch.js";

export type HarnessId = string;

export interface TurnInput {
  systemPrompt: string; // base Isolation prompt + the user prompt, already merged
  history: { role: "user" | "assistant"; text: string }[];
  userText: string;
  agent: { id: string; name: string; model?: string };
  sandboxId?: string; // where the agent's tools execute (real harnesses use this)
  // The harness's own resumable session for THIS thread (claude-code's session id), if it has
  // one from an earlier turn — a real harness keeps its context there, not in `history`.
  harnessSession?: string;
  // The agent's credential as ENV (PLAN §5b): the gateway base URL for its slot + a placeholder
  // key the sidecar overwrites. Provided by the supervisor from the launch's sealed credentials.
  env?: Record<string, string>;
}

export interface TurnOutput {
  text: string;
  harnessSession?: string; // what to store on the thread for the next turn
}

export interface Harness {
  id: HarnessId;
  label: string;
  installed: boolean;
  runTurn(input: TurnInput): Promise<TurnOutput>;
}

// Built-in echo harness: proves the whole pipeline with no model credentials. It
// demonstrates that (a) the base+user system prompt reached the harness, (b) the agent's
// OWN history is what it sees (not another agent's), and (c) turns persist. It's not a
// toy stub in the wrong place — it's the deterministic fixture every real adapter is
// tested against, and the offline demo brain.
const echo: Harness = {
  id: "echo",
  label: "Echo (built-in, no credentials)",
  installed: true,
  async runTurn({ systemPrompt, history, userText, agent }) {
    const persona = (systemPrompt.split("\n\n").slice(1).join(" ").trim() || "(no user instructions)").slice(0, 120);
    const priorUser = history.filter((m) => m.role === "user").length;
    return {
      text: [
        `[${agent.name}] `,
        `you said: "${userText}". `,
        `I'm running as persona: ${persona}. `,
        `this is turn ${priorUser + 1} of MY conversation${agent.model ? ` (model ${agent.model})` : ""}.`,
      ].join(""),
    };
  },
};

// Claude Code IN the sandbox (PLAN §5 P1): each turn is one `claude -p` run over execd, resumed
// from the thread's own claude session so the context lives in the sandbox with the code. The
// CLI is installed on first use (npm, cached in the image later — TOOLING_VERSION). Permissions
// are skipped: the sandbox IS the permission boundary. Credentials arrive as env — the agent's
// gateway slot; the real key never enters the container (the sidecar injects it).
const CLAUDE_INSTALL = 'command -v claude >/dev/null 2>&1 || npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || (command -v iso-node >/dev/null 2>&1 && "$(dirname "$(command -v iso-node)")/npm" install -g @anthropic-ai/claude-code >/dev/null 2>&1)';
export const shq = (v: string): string => `'${v.replace(/'/g, `'\\''`)}'`;
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
export const codexLoginFile = (accessToken: string, accountId: string): string =>
  `mkdir -p ~/.codex && printf '%s' ${shq(JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: codexIdToken(accountId), access_token: codexAccessToken(accessToken, accountId), refresh_token: "", account_id: accountId }, last_refresh: new Date().toISOString() }))} > ~/.codex/auth.json && chmod 600 ~/.codex/auth.json`;
const claudeCode: Harness = {
  id: "claude-code",
  label: "Claude Code (in the sandbox)",
  installed: true,
  async runTurn({ systemPrompt, userText, agent, sandboxId, harnessSession, env }) {
    if (!sandboxId) throw new Error("claude-code needs a running sandbox");
    const { run } = await import("./execd.js");
    const args = [
      "claude",
      "-p",
      shq(userText),
      "--output-format",
      "json",
      "--dangerously-skip-permissions",
      // The persona rides EVERY turn: a resumed claude session does not remember flags from the
      // turn that created it.
      "--append-system-prompt",
      shq(systemPrompt),
      ...(harnessSession ? ["--resume", shq(harnessSession)] : []),
      ...(agent.model ? ["--model", shq(agent.model)] : []),
    ];
    // An agent's credential replaces the WHOLE Anthropic pair (launch.ts AI_ENV_KEYS), exactly as
    // applyAiCred does host-side: the container already carries the SESSION's credential, and
    // `envs` can only ADD names. A leftover CLAUDE_CODE_OAUTH_TOKEN out-ranks the agent's key while
    // the agent's ANTHROPIC_BASE_URL redirects it — the session's raw OAuth token to the agent's
    // gateway slot. Clear every key of the pair the agent does not set itself.
    const unset = env && AI_ENV_KEYS.some((k) => k in env) ? AI_ENV_KEYS.filter((k) => !(k in env)).flatMap((k) => ["-u", k]) : [];
    const exe = unset.length ? ["env", ...unset, ...args] : args;
    // IS_SANDBOX: Claude Code's own switch for "I am inside a container" — without it, skipping
    // permissions is refused for root (which the sandbox user is).
    const r = await run(sandboxId, `${CLAUDE_INSTALL}; ${exe.join(" ")}`, { cwd: "/workspace", envs: { IS_SANDBOX: "1", ...(env ?? {}) }, timeoutMs: 15 * 60_000 });
    // `--output-format json` prints ONE object: { type: "result", result, session_id, is_error … }.
    const line = r.stdout.split("\n").reverse().find((l) => l.trim().startsWith("{"));
    let parsed: { result?: string; session_id?: string; is_error?: boolean; subtype?: string } | undefined;
    try {
      parsed = line ? JSON.parse(line) : undefined;
    } catch {
      parsed = undefined;
    }
    if (!parsed) throw new Error((r.stderr || r.stdout).trim().split("\n").slice(-3).join(" / ").slice(0, 400) || "claude produced no result");
    if (parsed.is_error) throw new Error(parsed.result?.slice(0, 400) || `claude: ${parsed.subtype ?? "error"}`);
    return { text: parsed.result ?? "", harnessSession: parsed.session_id ?? harnessSession };
  },
};

// Codex IN the sandbox — the ChatGPT/OpenAI counterpart of claude-code: one `codex exec --json`
// per turn, resumed from the thread's own codex thread (`codex exec resume <id>`), the agent's
// instructions folded into the first prompt (codex exec has no system-prompt flag). Approvals
// and codex's own sandbox are bypassed: ours is the boundary. Credentials arrive as env — the
// OpenAI-shaped pair for the agent's gateway slot.
const codex: Harness = {
  id: "codex",
  label: "Codex (in the sandbox)",
  installed: true,
  async runTurn({ systemPrompt, userText, agent, sandboxId, harnessSession, env }) {
    if (!sandboxId) throw new Error("codex needs a running sandbox");
    const { run } = await import("./execd.js");
    // codex exec has no system-prompt flag and a resumed thread only sees the new prompt, so the
    // persona is restated on every turn as a leading instructions block.
    const prompt = `[Instructions for this session — follow them, they are not from the user]\n${systemPrompt}\n[End of instructions]\n\n${userText}`;
    // Codex's default provider dials api.openai.com over a websocket, ignoring OPENAI_BASE_URL —
    // so the gateway slot is declared as an explicit HTTP-only provider (Responses wire API,
    // key from OPENAI_API_KEY). Without a base URL in env, codex's own defaults apply.
    const base = env?.OPENAI_BASE_URL;
    const gatewayRoot = base?.replace(/\/v1\/?$/, "");
    // Two ways to the gateway: an API key rides an explicit HTTP-only provider (codex's default
    // dials api.openai.com over a websocket); a ChatGPT subscription keeps codex's own ChatGPT
    // mode but with `chatgpt_base_url` pointed at the gateway slot — codex sends its normal
    // `/backend-api/codex/…` requests there, logged in with a placeholder the gateway swaps.
    // ChatGPT mode through the gateway: codex's built-in provider speaks a websocket the gateway
    // cannot carry, so the slot is declared as a provider of our own in ChatGPT-auth mode
    // (requires_openai_auth) with websockets off — plain HTTPS to <slot>/backend-api/codex.
    const provider = env?.CODEX_SUBSCRIPTION && gatewayRoot
      ? [
          "-c", shq(`chatgpt_base_url="${gatewayRoot}/backend-api/"`),
          "-c", shq(`preferred_auth_method="chatgpt"`),
          "-c", "model_provider=iso",
          "-c", shq(`model_providers.iso={ name="iso", base_url="${gatewayRoot}/backend-api/codex", wire_api="responses", supports_websockets=false, requires_openai_auth=true }`),
        ]
      : base
        ? ["-c", "model_provider=iso", "-c", shq(`model_providers.iso={ name="iso", base_url="${base}", wire_api="responses", supports_websockets=false, env_key="OPENAI_API_KEY" }`)]
        : [];
    const login = env?.CODEX_SUBSCRIPTION ? `${codexLoginFile(env.OPENAI_API_KEY ?? "isolation-vault", env.CODEX_ACCOUNT_ID ?? "")}; ` : "";
    const common = ["--json", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", ...provider, "-C", "/workspace", ...(agent.model ? ["-m", shq(agent.model)] : [])];
    // `resume` is a subcommand that only takes -c overrides: every exec-level flag goes BEFORE it.
    const cmd = harnessSession
      ? ["codex", "exec", ...common.filter((a, i, arr) => !(a === "-c" || (i > 0 && arr[i - 1] === "-c"))), "resume", ...common.filter((a, i, arr) => a === "-c" || (i > 0 && arr[i - 1] === "-c")), shq(harnessSession), shq(prompt)]
      : ["codex", "exec", ...common, shq(prompt)];
    // In ChatGPT mode an OPENAI_API_KEY in the environment wins over the login file and flips
    // codex to API-key mode (straight to api.openai.com) — keep the key out of its env.
    // The container env may carry the session slot's key too — unset both in the command itself.
    const envs = env?.CODEX_SUBSCRIPTION ? Object.fromEntries(Object.entries(env).filter(([k]) => k !== "OPENAI_API_KEY" && k !== "OPENAI_BASE_URL")) : env;
    const exe = env?.CODEX_SUBSCRIPTION ? ["env", "-u", "OPENAI_API_KEY", "-u", "OPENAI_BASE_URL", ...cmd] : cmd;
    const r = await run(sandboxId, `${login}${exe.join(" ")}`, { cwd: "/workspace", envs, timeoutMs: 15 * 60_000 });
    // JSONL: thread.started {thread_id}; item.completed {item:{type:"agent_message", text}} — the
    // last agent message is the reply.
    let threadId: string | undefined;
    let text: string | undefined;
    for (const line of r.stdout.split("\n")) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      try {
        const ev = JSON.parse(t) as { type?: string; thread_id?: string; item?: { type?: string; text?: string }; error?: { message?: string } };
        if (ev.thread_id) threadId = ev.thread_id;
        if (ev.type === "item.completed" && ev.item?.type === "agent_message" && typeof ev.item.text === "string") text = ev.item.text;
        if (ev.type === "error" && ev.error?.message && !text) throw new Error(ev.error.message.slice(0, 400));
      } catch (e) {
        if ((e as Error).message && !(e instanceof SyntaxError)) throw e;
      }
    }
    if (text === undefined) throw new Error((r.stderr || r.stdout).trim().split("\n").slice(-3).join(" / ").slice(0, 400) || "codex produced no reply");
    return { text, harnessSession: threadId ?? harnessSession };
  },
};

const registry = new Map<HarnessId, Harness>([
  [echo.id, echo],
  [claudeCode.id, claudeCode],
  [codex.id, codex],
]);

// Register a real adapter (claude-code/codex/…) — called from wherever they're wired.
export function registerHarness(h: Harness): void {
  registry.set(h.id, h);
}

// Resolve a harness; an unknown id degrades to a harness that reports it's unavailable
// (so a turn fails with a clear message instead of a crash).
export function getHarness(id: HarnessId): Harness {
  return (
    registry.get(id) ?? {
      id,
      label: `${id} (not installed)`,
      installed: false,
      async runTurn() {
        throw new Error(`harness "${id}" is not installed in this session`);
      },
    }
  );
}

export const listHarnesses = (): { id: HarnessId; label: string; installed: boolean }[] =>
  [...registry.values()].map((h) => ({ id: h.id, label: h.label, installed: h.installed }));
