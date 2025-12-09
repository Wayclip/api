FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /app

RUN case "$TARGETPLATFORM" in \
        "linux/amd64")  export RUSTTARGET=x86_64-unknown-linux-gnu ;; \
        "linux/arm64")  export RUSTTARGET=aarch64-unknown-linux-gnu ;; \
        *) echo "Unsupported TARGETPLATFORM: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    echo "$RUSTTARGET" > /rust_target

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential pkg-config clang \
    && rm -rf /var/lib/apt/lists/*

RUN export RUSTTARGET=$(cat /rust_target) && \
if [ "$RUSTTARGET" = "aarch64-unknown-linux-gnu" ]; then \
        dpkg --add-architecture arm64 && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross \
            libssl-dev:arm64 \
            libpq-dev:arm64 \
            libssh2-1-dev:arm64 \
            libavcodec-dev:arm64 \
            libavformat-dev:arm64 \
            libavutil-dev:arm64 \
            libswscale-dev:arm64 \
            libavfilter-dev:arm64 \
            libavdevice-dev:arm64 \
            libswresample-dev:arm64 \
            libwayland-dev:arm64 \
            libxkbcommon-dev:arm64 \
            libpipewire-0.3-dev:arm64 \
            libdbus-1-dev:arm64 \
            libgstreamer1.0-dev:arm64 \
            libgstreamer-plugins-base1.0-dev:arm64 \
            libx11-dev:arm64 \
            libxrandr-dev:arm64 \
            libxtst-dev:arm64 \
            libasound2-dev:arm64 \
            lld && \
        rm -rf /var/lib/apt/lists/* && \
        rustup target add aarch64-unknown-linux-gnu && \
        mkdir -p /app/.cargo && \
        echo '[target.aarch64-unknown-linux-gnu]' >> /app/.cargo/config.toml && \
        echo 'linker = "aarch64-linux-gnu-gcc"' >> /app/.cargo/config.toml && \
        echo 'ar = "aarch64-linux-gnu-ar"' >> /app/.cargo/config.toml && \
        echo 'rustflags = ["-C", "link-arg=-fuse-ld=lld"]' >> /app/.cargo/config.toml && \
        echo '#!/bin/sh' > /usr/bin/aarch64-unknown-linux-gnu-pkg-config && \
        echo 'PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig \' >> /usr/bin/aarch64-unknown-linux-gnu-pkg-config && \
        echo 'exec pkg-config "$@"' >> /usr/bin/aarch64-unknown-linux-gnu-pkg-config && \
        chmod +x /usr/bin/aarch64-unknown-linux-gnu-pkg-config; \
    else \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            libssl-dev \
            libpq-dev \
            libssh2-1-dev \
            libavcodec-dev \
            libavformat-dev \
            libavutil-dev \
            libswscale-dev \
            libavfilter-dev \
            libavdevice-dev \
            libswresample-dev \
            libwayland-dev \
            libxkbcommon-dev \
            libpipewire-0.3-dev \
            libdbus-1-dev \
            libgstreamer1.0-dev \
            libgstreamer-plugins-base1.0-dev \
            libx11-dev \
            libxrandr-dev \
            libxtst-dev \
            libasound2-dev && \
        rm -rf /var/lib/apt/lists/*; \
    fi

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch

COPY .sqlx ./.sqlx
COPY src ./src
COPY assets ./assets
COPY migrations ./migrations

ENV SQLX_OFFLINE=true

RUN export RUSTTARGET=$(cat /rust_target) && \
    if [ "$RUSTTARGET" = "aarch64-unknown-linux-gnu" ]; then \
        export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc" && \
        export CXX_aarch64_unknown_linux_gnu="aarch64-linux-gnu-g++"; \
    fi && \
    cargo build --release --target $RUSTTARGET

RUN mkdir /out && \
    cp target/$(cat /rust_target)/release/wayclip-api /out/

FROM --platform=$TARGETPLATFORM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 libssh2-1 ffmpeg \
    libwayland-client0 libxkbcommon0 libpipewire-0.3-0 libdbus-1-3 \
    libgstreamer1.0-0 libgstreamer-plugins-base1.0-0 \
    libx11-6 libxrandr2 libxtst6 libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /out/wayclip-api /usr/local/bin/
COPY --from=builder /app/assets ./assets
COPY --from=builder /app/migrations ./migrations
ENTRYPOINT ["/usr/local/bin/wayclip-api"]
