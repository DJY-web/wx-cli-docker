FROM rust:1.95-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENV CARGO_TARGET_DIR=/target
