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

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    COMMON_LIBS="libssl-dev libpq-dev libssh2-1-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev libavfilter-dev libavdevice-dev libswresample-dev libwayland-dev libxkbcommon-dev libpipewire-0.3-dev libdbus-1-dev libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libx11-dev libxrandr-dev libxtst-dev libasound2-dev" && \
    case "$TARGETPLATFORM" in \
        "linux/arm64") \
            dpkg --add-architecture arm64 && \
            apt-get update && \
            apt-get install -y --no-install-recommends \
                build-essential pkg-config clang \
                gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross \
                pkg-config-aarch64-linux-gnu \
                $(echo $COMMON_LIBS | sed -e 's/\([^ ]*\)/\1:arm64/g'); \
            ;; \
        "linux/amd64") \
            apt-get install -y --no-install-recommends \
                build-essential pkg-config clang \
                $COMMON_LIBS; \
            ;; \
        *) echo "Unsupported architecture" && exit 1 ;; \
    esac \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add aarch64-unknown-linux-gnu

RUN mkdir -p .cargo && \
    echo '[target.aarch64-unknown-linux-gnu]' >> .cargo/config.toml && \
    echo 'linker = "aarch64-linux-gnu-gcc"' >> .cargo/config.toml && \
    echo 'rustflags = ["-C", "link-arg=-fuse-ld=lld"]' >> .cargo/config.toml

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
        export PKG_CONFIG="aarch64-linux-gnu-pkg-config"; \
    fi && \
    cargo build --release --target $RUSTTARGET

RUN mkdir /out && \
    cp target/$(cat /rust_target)/release/wayclip-api /out/

FROM debian:bookworm-slim

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
