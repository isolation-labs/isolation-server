// The agent view's state (PLAN §5d): one zustand/vanilla store per page, fed by ACP
// `session/update` notifications (live or replayed) and the bridge's `_iso/*` notifications.
// Framework-agnostic on purpose — the reducer is the one place the ACP surface is interpreted.
import { createStore } from "zustand/vanilla";
import { rememberFile } from "./markdown.js";
import type { AvailableCommand, ContentBlock, PlanEntry, RequestPermissionRequest, RequestPermissionResponse, SessionConfigOption, SessionModeState, SessionNotification, SessionUpdate, ToolCallContent, ToolCallLocation, ToolKind, ToolCallStatus } from "@agentclientprotocol/sdk";

export interface ToolCallState {
  toolCallId: string;
  title: string;
  kind?: ToolKind | null;
  status?: ToolCallStatus | null;
  content: ToolCallContent[];
  locations: ToolCallLocation[];
  rawInput?: unknown;
  rawOutput?: unknown;
}

export type Item =
  | { kind: "user"; id: string; text: string; from?: string; ts?: number }
  | { kind: "agent"; id: string; text: string; thought: string }
  | { kind: "tool"; id: string; call: ToolCallState }
  | { kind: "note"; id: string; text: string };

export interface PermissionReq {
  id: string;
  request: RequestPermissionRequest;
  resolve: (r: RequestPermissionResponse) => void;
}

export type Phase = "connecting" | "idle" | "starting" | "ready" | "stopped" | "error";

export interface AgentMeta {
  id: string;
  name: string;
  harness: string;
  model: string | null;
}

export interface State {
  phase: Phase;
  error?: string;
  connected: boolean;
  agent?: AgentMeta;
  sessionId?: string;
  modes: SessionModeState | null;
  configOptions: SessionConfigOption[] | null;
  commands: AvailableCommand[];
  items: Item[];
  plan: PlanEntry[] | null;
  turn: { active: boolean; from?: string };
  permissions: PermissionReq[];
  usage: unknown;
  truncated: boolean;
  // A prompt this window sent, not yet echoed by the bridge (optimistic render).
  pendingPrompt?: string;
}

let seq = 0;
const nid = () => `i${++seq}`;

const textOf = (b: ContentBlock): string => {
  if (b.type === "text") return b.text;
  if (b.type === "resource_link") return `[${b.name ?? b.uri}](${b.uri})`;
  if (b.type === "resource") return "resource" in b && b.resource && "text" in b.resource ? String((b.resource as { text?: string }).text ?? "") : "[resource]";
  if (b.type === "image") return "[image]";
  if (b.type === "audio") return "[audio]";
  return "";
};

export const store = createStore<State>(() => ({
  phase: "connecting",
  connected: false,
  modes: null,
  configOptions: null,
  commands: [],
  items: [],
  plan: null,
  turn: { active: false },
  permissions: [],
  usage: undefined,
  truncated: false,
}));

const set = store.setState;
const get = store.getState;

export function resetConversation(): void {
  set({ items: [], plan: null, truncated: false });
}

// One ACP update → the item list. Consecutive chunks of one role coalesce into one item; a tool
// call (or the other role) starts a new one — the same grouping a transcript reader expects.
export function applyUpdate(u: SessionUpdate, meta?: { from?: string; ts?: number }): void {
  const s = get();
  const items = s.items;
  const last = items[items.length - 1];
  switch (u.sessionUpdate) {
    case "user_message_chunk": {
      const t = textOf(u.content);
      if (last?.kind === "user" && last.from === meta?.from && !("messageId" in u && u.messageId && last.id !== u.messageId)) {
        set({ items: [...items.slice(0, -1), { ...last, text: last.text + t }], pendingPrompt: undefined });
      } else set({ items: [...items, { kind: "user", id: u.messageId ?? nid(), text: t, from: meta?.from, ts: meta?.ts }], pendingPrompt: undefined });
      return;
    }
    case "agent_message_chunk": {
      const t = textOf(u.content);
      if (last?.kind === "agent") set({ items: [...items.slice(0, -1), { ...last, text: last.text + t }] });
      else set({ items: [...items, { kind: "agent", id: nid(), text: t, thought: "" }] });
      return;
    }
    case "agent_thought_chunk": {
      const t = textOf(u.content);
      if (last?.kind === "agent") set({ items: [...items.slice(0, -1), { ...last, thought: last.thought + t }] });
      else set({ items: [...items, { kind: "agent", id: nid(), text: "", thought: t }] });
      return;
    }
    case "tool_call": {
      for (const l of u.locations ?? []) rememberFile(l.path);
      const idx = items.findIndex((i) => i.kind === "tool" && i.call.toolCallId === u.toolCallId);
      const call: ToolCallState = { toolCallId: u.toolCallId, title: u.title, kind: u.kind ?? null, status: u.status ?? "pending", content: u.content ?? [], locations: u.locations ?? [], rawInput: u.rawInput, rawOutput: u.rawOutput };
      if (idx >= 0) set({ items: items.map((i, k) => (k === idx ? { kind: "tool", id: i.id, call } : i)) });
      else set({ items: [...items, { kind: "tool", id: nid(), call }] });
      return;
    }
    case "tool_call_update": {
      for (const l of u.locations ?? []) rememberFile(l.path);
      let idx = -1;
      for (let k = items.length - 1; k >= 0; k--) {
        const i = items[k];
        if (i.kind === "tool" && i.call.toolCallId === u.toolCallId) {
          idx = k;
          break;
        }
      }
      if (idx < 0) {
        set({ items: [...items, { kind: "tool", id: nid(), call: { toolCallId: u.toolCallId, title: u.title ?? "tool", kind: u.kind ?? null, status: u.status ?? "in_progress", content: u.content ?? [], locations: u.locations ?? [], rawInput: u.rawInput, rawOutput: u.rawOutput } }] });
        return;
      }
      const cur = (items[idx] as Extract<Item, { kind: "tool" }>).call;
      const call: ToolCallState = {
        ...cur,
        ...(u.title ? { title: u.title } : {}),
        ...(u.kind ? { kind: u.kind } : {}),
        ...(u.status ? { status: u.status } : {}),
        ...(u.content ? { content: u.content } : {}),
        ...(u.locations ? { locations: u.locations } : {}),
        ...(u.rawInput !== undefined ? { rawInput: u.rawInput } : {}),
        ...(u.rawOutput !== undefined ? { rawOutput: u.rawOutput } : {}),
      };
      set({ items: items.map((i, k) => (k === idx ? { kind: "tool", id: i.id, call } : i)) });
      return;
    }
    case "plan":
      set({ plan: u.entries });
      return;
    case "plan_update": {
      const entries = (u as unknown as { entries?: PlanEntry[] }).entries;
      if (Array.isArray(entries)) set({ plan: entries });
      return;
    }
    case "plan_removed":
      set({ plan: null });
      return;
    case "available_commands_update":
      set({ commands: u.availableCommands });
      return;
    case "current_mode_update":
      set({ modes: s.modes ? { ...s.modes, currentModeId: u.currentModeId } : s.modes });
      return;
    case "config_option_update":
      set({ configOptions: u.configOptions });
      return;
    case "usage_update":
      set({ usage: u });
      return;
    case "compaction_update": {
      const st = (u as unknown as { status?: string }).status;
      if (st === "started" || st === "completed") set({ items: [...items, { kind: "note", id: nid(), text: st === "started" ? "Compacting context…" : "Context compacted" }] });
      return;
    }
    default:
      return;
  }
}

export function applyNotification(n: SessionNotification): void {
  const iso = (n._meta as { iso?: { from?: string; ts?: number } } | null | undefined)?.iso;
  applyUpdate(n.update, iso);
}

export interface Hello {
  viewId: string;
  agent: AgentMeta | null;
  sessionId: string | null;
  session: { modes?: SessionModeState | null; configOptions?: SessionConfigOption[] | null } | null;
  phase: Phase;
  error?: string;
  turn: { active: boolean; from?: string };
  truncated: boolean;
  updates: { method: string; params: SessionNotification }[];
}

export function hydrate(h: Hello): void {
  set({
    agent: h.agent ?? get().agent,
    sessionId: h.sessionId ?? undefined,
    modes: h.session?.modes ?? null,
    configOptions: h.session?.configOptions ?? null,
    phase: h.phase,
    error: h.error,
    turn: h.turn,
    items: [],
    plan: null,
    truncated: h.truncated,
    permissions: [],
  });
  for (const u of h.updates) if (u.method === "session/update") applyNotification(u.params);
}

export function addPermission(request: RequestPermissionRequest, resolve: (r: RequestPermissionResponse) => void, id: string): void {
  set({ permissions: [...get().permissions, { id, request, resolve }] });
}
export function answerPermission(id: string, optionId?: string): void {
  const p = get().permissions.find((x) => x.id === id);
  if (!p) return;
  set({ permissions: get().permissions.filter((x) => x.id !== id) });
  p.resolve(optionId ? { outcome: { outcome: "selected", optionId } } : { outcome: { outcome: "cancelled" } });
}

export const setPhase = (phase: Phase, error?: string): void => set({ phase, error });
export const setConnected = (connected: boolean): void => set({ connected });
export const setTurn = (turn: { active: boolean; from?: string }): void => set({ turn });
export const setSession = (sessionId: string, session: Hello["session"]): void => set({ sessionId, modes: session?.modes ?? get().modes, configOptions: session?.configOptions ?? get().configOptions });
export const setPending = (text?: string): void => set({ pendingPrompt: text });
