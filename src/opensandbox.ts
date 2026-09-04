// Thin client for the local opensandbox-server. isolation-server never reimplements anything
// the runtime already does — if it can be expressed as a call here, it must be.
import { getOsb } from "./config.js";

export interface SandboxStatus {
  state: string;
  reason?: string;
  message?: string;
}

export interface Sandbox {
  id: string;
  status: SandboxStatus;
  metadata?: Record<string, string>;
  expiresAt?: string | null;
  createdAt: string;
}

export interface CreateSandboxSpec {
  image: string;
  entrypoint: string[];
  cpu?: string;
  memory?: string;
  env?: Record<string, string>;
  metadata?: Record<string, string>;
  timeoutSec?: number | null;
  // The egress sidecar (PLAN §5b): an outbound policy attaches it; credentialProxy turns on
  // the transparent MITM the Credential Vault injects through. Both or neither.
  networkPolicy?: { defaultAction: "allow" | "deny"; egress: { action: string; target: string }[] };
  credentialProxy?: { enabled: boolean };
}

class OsbError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const { url, apiKey } = getOsb();
  const r = await fetch(`${url.replace(/\/+$/, "")}${path}`, {
    method,
    headers: {
      ...(apiKey ? { "OPEN-SANDBOX-API-KEY": apiKey } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    throw new OsbError(r.status, `opensandbox ${method} ${path} → HTTP ${r.status}${detail ? `: ${detail.slice(0, 300)}` : ""}`);
  }
  // Some lifecycle endpoints answer 200 with an empty body — tolerate both.
  const text = await r.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const osbHealthy = async (): Promise<boolean> => {
  try {
    const { url } = getOsb();
    const r = await fetch(`${url.replace(/\/+$/, "")}/health`);
    return r.ok;
  } catch {
    return false;
  }
};

export function createSandbox(spec: CreateSandboxSpec): Promise<Sandbox> {
  return call<Sandbox>("POST", "/v1/sandboxes", {
    image: { uri: spec.image },
    entrypoint: spec.entrypoint,
    resourceLimits: { cpu: spec.cpu ?? "2", memory: spec.memory ?? "2Gi" },
    ...(spec.env ? { env: spec.env } : {}),
    ...(spec.metadata ? { metadata: spec.metadata } : {}),
    ...(spec.networkPolicy ? { networkPolicy: spec.networkPolicy } : {}),
    ...(spec.credentialProxy ? { credentialProxy: spec.credentialProxy } : {}),
    timeout: spec.timeoutSec === undefined ? 86400 : spec.timeoutSec,
  });
}

export const getSandbox = (id: string): Promise<Sandbox> => call<Sandbox>("GET", `/v1/sandboxes/${id}`);
export const deleteSandbox = (id: string): Promise<void> => call<void>("DELETE", `/v1/sandboxes/${id}`);
export const pauseSandbox = (id: string): Promise<void> => call<void>("POST", `/v1/sandboxes/${id}/pause`);
export const resumeSandbox = (id: string): Promise<void> => call<void>("POST", `/v1/sandboxes/${id}/resume`);

export async function listSandboxes(): Promise<Sandbox[]> {
  const page = await call<{ items: Sandbox[] }>("GET", "/v1/sandboxes?pageSize=100");
  return page.items;
}

// Container logs via the runtime's diagnostics API (raw text tail).
export async function sandboxLogs(id: string, tail = 500): Promise<string> {
  const { url, apiKey } = getOsb();
  const r = await fetch(`${url.replace(/\/+$/, "")}/v1/sandboxes/${id}/diagnostics/logs?tail=${tail}`, {
    headers: apiKey ? { "OPEN-SANDBOX-API-KEY": apiKey } : {},
  });
  if (!r.ok) throw new OsbError(r.status, `diagnostics logs → HTTP ${r.status}`);
  return r.text();
}

// Resolve where a sandbox port is reachable FROM THIS HOST. Docker runtime, direct
// ingress: the runtime returns "<host>:<publishedPort>/proxy/<port>" — the published
// port belongs to the in-sandbox execd, whose /proxy/<port> path forwards to the app
// port inside. The doorman proxies to exactly this target.
export interface Endpoint {
  host: string; // e.g. 127.0.0.1:50870
  basePath: string; // e.g. /proxy/8000
}

export async function endpointFor(sandboxId: string, port: number): Promise<Endpoint> {
  return endpointWithHeaders(sandboxId, port);
}

// Same, plus the auth headers the runtime hands out for a port that needs them (the egress
// sidecar's API on 18080 answers only with its per-sandbox `OPENSANDBOX-EGRESS-AUTH`).
export async function endpointWithHeaders(sandboxId: string, port: number): Promise<Endpoint & { headers: Record<string, string> }> {
  const { endpoint, headers } = await call<{ endpoint: string; headers?: Record<string, string> }>("GET", `/v1/sandboxes/${sandboxId}/endpoints/${port}`);
  const slash = endpoint.indexOf("/");
  const h = headers ?? {};
  if (slash === -1) return { host: endpoint, basePath: "", headers: h };
  return { host: endpoint.slice(0, slash), basePath: endpoint.slice(slash).replace(/\/+$/, ""), headers: h };
}
