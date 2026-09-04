# isolation-server tooling image — the minimal layer a session needs for the shipped views:
# git (clones), tmux + ttyd (terminal view), filebrowser (directory view). The code
# view is doorman-served Monaco (PLAN V1) — nothing in the image. Language runtimes
# come from the workspace's own devcontainer image later (O4).
FROM debian:bookworm-slim
ARG TARGETARCH
ARG TTYD_VERSION=1.7.7
RUN apt-get update && apt-get install -y --no-install-recommends \
    git tmux curl ca-certificates openssh-client procps xz-utils bzip2 \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$([ "$TARGETARCH" = "arm64" ] && echo aarch64 || echo x86_64)" \
    && curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.${arch}" \
    && chmod +x /usr/local/bin/ttyd \
    && curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash \
    && mkdir -p /workspace
# Batteries (interim, until the devcontainer pipeline builds per-workspace images —
# PLAN O4): Node LTS + Python/uv so a freshly-cloned repo can `npm install` today.
ARG NODE_VERSION=22.12.0
RUN arch="$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
    && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
       | tar -xJ -C /usr/local --strip-components=1 --exclude='*/CHANGELOG.md' --exclude='*/README.md' \
    && apt-get update && apt-get install -y --no-install-recommends python3 python3-pip python3-venv build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
# The native agent CLIs (PLAN §5): a subscription runs its own harness — claude (Claude Code)
# and codex — so they are always here, whatever the workspace's language stack. The ACP
# adapters (PLAN §5d) are what the agent view actually drives — pinned, since the ACP
# surface still moves — and goose is the ACP agent for every other provider's API key.
ARG CLAUDE_ACP_VERSION=0.73.0
ARG CODEX_ACP_VERSION=1.8.0
ARG GOOSE_VERSION=1.49.0
RUN npm install -g --no-fund --no-audit @anthropic-ai/claude-code @openai/codex \
    @agentclientprotocol/claude-agent-acp@${CLAUDE_ACP_VERSION} @agentclientprotocol/codex-acp@${CODEX_ACP_VERSION}
RUN arch="$([ "$TARGETARCH" = "arm64" ] && echo aarch64 || echo x86_64)" \
    && mkdir -p /tmp/goose && curl -fsSL "https://github.com/block/goose/releases/download/v${GOOSE_VERSION}/goose-${arch}-unknown-linux-gnu.tar.bz2" \
       | tar -xj -C /tmp/goose && mv /tmp/goose/goose /usr/local/bin/goose && chmod +x /usr/local/bin/goose && rm -rf /tmp/goose
WORKDIR /workspace
