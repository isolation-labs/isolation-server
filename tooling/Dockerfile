# isogate tooling image — the minimal layer a session needs for the shipped views:
# git (clones), tmux + ttyd (the terminal view's live-mirror transport). Kept small;
# language runtimes come from the workspace's own devcontainer image later (O4).
FROM debian:bookworm-slim
ARG TARGETARCH
ARG TTYD_VERSION=1.7.7
RUN apt-get update && apt-get install -y --no-install-recommends \
    git tmux curl ca-certificates openssh-client procps \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$([ "$TARGETARCH" = "arm64" ] && echo aarch64 || echo x86_64)" \
    && curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.${arch}" \
    && chmod +x /usr/local/bin/ttyd \
    && mkdir -p /workspace
WORKDIR /workspace
