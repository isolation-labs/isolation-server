# isolation-server tooling image — the minimal layer a session needs for the shipped views:
# git (clones), tmux + ttyd (terminal view), filebrowser (directory view). The code
# view is doorman-served Monaco (PLAN V1) — nothing in the image. Language runtimes
# come from the workspace's own devcontainer image later (O4).
FROM debian:bookworm-slim
ARG TARGETARCH
ARG TTYD_VERSION=1.7.7
RUN apt-get update && apt-get install -y --no-install-recommends \
    git tmux curl ca-certificates openssh-client procps xz-utils \
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
WORKDIR /workspace
