FROM rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential pkg-config clang \
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
    rm -rf /var/lib/apt/lists/*

RUN cargo install sqlx-cli --no-default-features --features postgres

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch

COPY .sqlx ./.sqlx
COPY src ./src
COPY assets ./assets
COPY migrations ./migrations

ENV SQLX_OFFLINE=true

RUN cargo build --release

RUN mkdir /out && \
    cp target/release/wayclip-api /out/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 libssh2-1 ffmpeg \
    libwayland-client0 libxkbcommon0 libpipewire-0.3-0 libdbus-1-3 \
    libgstreamer1.0-0 libgstreamer-plugins-base1.0-0 \
    libx11-6 libxrandr2 libxtst6 libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /out/wayclip-api /usr/local/bin/
COPY --from=builder /usr/local/cargo/bin/sqlx /usr/local/bin/
COPY --from=builder /app/assets ./assets
COPY --from=builder /app/migrations ./migrations

ENTRYPOINT ["/usr/local/bin/wayclip-api"]
