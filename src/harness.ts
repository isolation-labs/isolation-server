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
}

export interface Harness {
  id: HarnessId;
  label: string;
  installed: boolean;
  runTurn(input: TurnInput): Promise<string>;
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
    return [
      `[${agent.name}] `,
      `you said: "${userText}". `,
      `I'm running as persona: ${persona}. `,
      `this is turn ${priorUser + 1} of MY conversation${agent.model ? ` (model ${agent.model})` : ""}.`,
    ].join("");
  },
};

const registry = new Map<HarnessId, Harness>([[echo.id, echo]]);

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
