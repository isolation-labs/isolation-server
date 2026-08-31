# isolation-server

The [Isolation](https://isolation.cloud) server: the light layer between Isolation
Cloud and an [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) runtime.

OpenSandbox runs the sandboxes (lifecycle, exec, files, snapshots). isolation-server
adds the few things a cloud-driven, browser-facing server needs on top — and nothing
else:

- **Pairing + heartbeat** — link the server to an account with one command; it phones
  home, self-heals its public URL, reports its version, and detaches cleanly when
  removed.
- **The relay tunnel** — a Cloudflare tunnel fronting the gate, so browsers reach the
  server without any inbound firewall/port setup.
- **The doorman** — one public origin for every view of every sandbox
  (`/v/<viewId>/*`), WebSocket-capable, authorized by short-lived view tokens instead
  of the machine credential.
- **Launch orchestration** — sealed launch secrets (env vars + secret files),
  repo clones whose credentials never touch argv or URLs, devcontainer-derived
  images, and per-view processes (terminal = ttyd + tmux, code = code-server,
  files = filebrowser, web = the app itself).
- **Workspace persistence** — `/workspace` is a git repo bundled to an HTTP blob
  sink (`GET/PUT {endpoint}/{workspaceId}`, ETag compare-and-swap, end-to-end
  encrypted). Sessions work on `session/<id>` branches; save merges back and pushes
  the bundle. Wipe the server's disk and nothing is lost.

Everything that *can* be an OpenSandbox call *is* one — isolation-server never
reimplements the runtime.

## Install

```
npm install -g isolation-server
isolation connect <token-from-the-web-app>
```

That's the whole server: `connect` pairs it and runs `up`, which installs the pinned
OpenSandbox runtime (via uv), mints its API key, and registers both as login
services. Prerequisites: Node 20+ and Docker. State lives in `~/.isolation-server`.

Other verbs: `isolation up | down | status | update | disconnect`.

## Develop

```
npm install && npm run build
node dist/index.js            # the gate, foreground, on 127.0.0.1:8090
npm test                      # typecheck happens in CI; tests run over dist/
```

## License

Apache 2.0.
