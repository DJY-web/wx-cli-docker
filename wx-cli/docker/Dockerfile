FROM rust:1.95-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p wx-cli && strip target/release/wx-cli

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="wx-cli Docker" \
    org.opencontainers.image.source="https://github.com/DJY-web/wx-cli-docker" \
    org.opencontainers.image.licenses="MIT"
COPY LICENSE /usr/share/licenses/wx-cli/LICENSE
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 wxcli && useradd -m -u 1000 -g 1000 wxcli \
    && mkdir /state && chown wxcli:wxcli /state
COPY --from=build /src/target/release/wx-cli /usr/local/bin/wx-cli
COPY docker/server.sh /usr/local/bin/wx-cli-server
RUN chmod 755 /usr/local/bin/wx-cli-server
ENV XDG_CONFIG_HOME=/state/config XDG_CACHE_HOME=/state/cache XDG_STATE_HOME=/state/state \
    WX_CLI_WECHAT_DATA_ROOT=/config/xwechat_files
USER 1000:1000
ENTRYPOINT ["wx-cli"]
CMD ["--help"]
