# isogate

The light layer between [Isolation Cloud](https://isolation.cloud) and an
[OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) server.

OpenSandbox runs the sandboxes (lifecycle, exec, files, snapshots). isogate adds the
few things a cloud-driven, browser-facing server needs on top — and nothing else:

- **Pairing + heartbeat** — link the server to an account with one command; it phones
  home, self-heals its public URL, and detaches cleanly when removed.
- **The relay tunnel** — a free Cloudflare quick tunnel fronting the gate, so browsers
  reach the server without any inbound firewall/port setup.
- **The doorman** — one public origin for every view of every sandbox
  (`/v/<viewId>/*`), WebSocket-capable, authorized by short-lived view tokens instead
  of the machine credential.
- **Launch orchestration** — sealed launch secrets (env vars + secret files),
  repo clones whose credentials never touch argv or URLs, and per-view processes
  (terminal = ttyd + tmux, code = code-server) from the `isogate/tooling` image.
- **Workspace persistence** — `/workspace` is a git repo bundled to an HTTP blob
  sink (`GET/PUT {endpoint}/{workspaceId}`, ETag compare-and-swap). Sessions work
  on `session/<id>` branches; save merges back and pushes the bundle.

Everything that *can* be an OpenSandbox call *is* one — isogate never reimplements
the runtime.

## Run

```
npm install && npm run build
node dist/index.js            # the gate, on 127.0.0.1:8090
node dist/cli.js status
node dist/cli.js connect <token-from-the-web-app>
```

Requires a local `opensandbox-server` (see `~/.isogate/config.json` → `osb`).

## License

Apache 2.0.
