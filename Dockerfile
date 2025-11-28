FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

ARG TARGETPLATFORM
ARG TARGETARCH

WORKDIR /usr/src/app
RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        dpkg --add-architecture arm64 && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            build-essential pkg-config libclang-15-dev \
            gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross \
            libssl-dev:arm64 libpq-dev:arm64 libssh2-1-dev:arm64 \
            libavcodec-dev:arm64 libavformat-dev:arm64 libavutil-dev:arm64 libswscale-dev:arm64 libavfilter-dev:arm64 libavdevice-dev:arm64 libswresample-dev:arm64 \
            libwayland-dev:arm64 libxkbcommon-dev:arm64 libpipewire-0.3-dev:arm64 libdbus-1-dev:arm64 \
            libgstreamer1.0-dev:arm64 libgstreamer-plugins-base1.0-dev:arm64 \
            libx11-dev:arm64 libxrandr-dev:arm64 libxtst-dev:arm64 libasound2-dev:arm64; \
    else \
        apt-get install -y --no-install-recommends \
            build-essential pkg-config libclang-15-dev \
            libssl-dev libpq-dev libssh2-1-dev \
            libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libavfilter-dev libavdevice-dev libswresample-dev \
            libwayland-dev libxkbcommon-dev libpipewire-0.3-dev libdbus-1-dev \
            libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
            libx11-dev libxrandr-dev libxtst-dev libasound2-dev; \
    fi && \
    rm -rf /var/lib/apt/lists/*
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        rustup target add aarch64-unknown-linux-gnu && \
        mkdir -p .cargo && \
        echo '[target.aarch64-unknown-linux-gnu]' >> .cargo/config.toml && \
        echo 'linker = "aarch64-linux-gnu-gcc"' >> .cargo/config.toml; \
    fi
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
COPY .sqlx ./.sqlx
COPY src ./src
COPY assets ./assets
COPY migrations ./migrations

ENV SQLX_OFFLINE=true

RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        cargo build --release --target aarch64-unknown-linux-gnu; \
    else \
        cargo build --release; \
    fi

RUN mkdir /out && \
    if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        cp target/aarch64-unknown-linux-gnu/release/wayclip-api /out/; \
    else \
        cp target/release/wayclip-api /out/; \
    fi
