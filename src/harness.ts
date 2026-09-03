// The harness abstraction (PLAN O5 — agnostic brains). An agent names a harness; the
// supervisor runs a turn through it. One tiny interface keeps the model model-agnostic:
// `echo` is built in (deterministic, zero credentials — the credential-free test + demo
// path); real adapters (claude-code / codex / gemini over ACP, or a CLI in the sandbox)
// implement the SAME interface and register here. An unknown/uninstalled harness reports
// itself rather than vanishing — the same "(not installed)" honesty as the catalog.
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
const shq = (v: string): string => `'${v.replace(/'/g, `'\\''`)}'`;
// Codex's login file for a ChatGPT subscription: the (gateway) token as the access token — the
// gateway resolves the real OAuth — plus the account id the backend keys the plan off.
export const codexLoginFile = (accessToken: string, accountId: string): string =>
  `mkdir -p ~/.codex && printf '%s' ${shq(JSON.stringify({ OPENAI_API_KEY: null, tokens: { id_token: "", access_token: accessToken, refresh_token: "", account_id: accountId }, last_refresh: new Date().toISOString() }))} > ~/.codex/auth.json`;
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
      ...(harnessSession ? ["--resume", shq(harnessSession)] : ["--append-system-prompt", shq(systemPrompt)]),
      ...(agent.model ? ["--model", shq(agent.model)] : []),
    ];
    // IS_SANDBOX: Claude Code's own switch for "I am inside a container" — without it, skipping
    // permissions is refused for root (which the sandbox user is).
    const r = await run(sandboxId, `${CLAUDE_INSTALL}; ${args.join(" ")}`, { cwd: "/workspace", envs: { IS_SANDBOX: "1", ...(env ?? {}) }, timeoutMs: 15 * 60_000 });
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
    const prompt = harnessSession ? userText : `${systemPrompt}\n\n${userText}`;
    // Codex's default provider dials api.openai.com over a websocket, ignoring OPENAI_BASE_URL —
    // so the gateway slot is declared as an explicit HTTP-only provider (Responses wire API,
    // key from OPENAI_API_KEY). Without a base URL in env, codex's own defaults apply.
    const base = env?.OPENAI_BASE_URL;
    const gatewayRoot = base?.replace(/\/v1\/?$/, "");
    // Two ways to the gateway: an API key rides an explicit HTTP-only provider (codex's default
    // dials api.openai.com over a websocket); a ChatGPT subscription keeps codex's own ChatGPT
    // mode but with `chatgpt_base_url` pointed at the gateway slot — codex sends its normal
    // `/backend-api/codex/…` requests there, logged in with a placeholder the gateway swaps.
    const provider = env?.CODEX_SUBSCRIPTION && gatewayRoot
      ? ["-c", shq(`chatgpt_base_url="${gatewayRoot}/backend-api/"`)]
      : base
        ? ["-c", "model_provider=iso", "-c", shq(`model_providers.iso={ name="iso", base_url="${base}", wire_api="responses", supports_websockets=false, env_key="OPENAI_API_KEY" }`)]
        : [];
    const login = env?.CODEX_SUBSCRIPTION ? `${codexLoginFile(env.OPENAI_API_KEY ?? "isolation-vault", env.CODEX_ACCOUNT_ID ?? "")}; ` : "";
    const common = ["--json", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", ...provider, "-C", "/workspace", ...(agent.model ? ["-m", shq(agent.model)] : [])];
    const cmd = harnessSession
      ? ["codex", "exec", "resume", ...common, shq(harnessSession), shq(prompt)]
      : ["codex", "exec", ...common, shq(prompt)];
    const r = await run(sandboxId, `${login}${cmd.join(" ")}`, { cwd: "/workspace", envs: env, timeoutMs: 15 * 60_000 });
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
