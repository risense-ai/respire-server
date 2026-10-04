# respire-server API image (linux/amd64).
# Build context: repository root. docker build -f service/Dockerfile .
# Frontend source and publishing belong to risense-ai/respire-site.

FROM rust:1.95.0-trixie AS builder
# CI supplies an exact verified checkout SHA. Ad-hoc builds remain unknown.
ARG RESPIRE_BUILD_REVISION=unknown
ENV RESPIRE_BUILD_REVISION=$RESPIRE_BUILD_REVISION
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY . .
ENV RESPIRE_CORE_SDK_DIR=/src/.sdk/x86_64-unknown-linux-gnu
RUN node scripts/fetch-core-sdk.mjs x86_64-unknown-linux-gnu
RUN cargo build --release --locked -p respire_service --bin respire-server \
    && mkdir -p /out/bin \
    && cp target/release/respire-server /out/bin/respire-server \
    && node scripts/stage-core-runtime.mjs /out/bin \
    && mkdir -p /out/runtime \
    && cp -a "$RESPIRE_CORE_SDK_DIR/runtime/." /out/runtime/

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libstdc++6 libgomp1 wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 respire \
    && useradd --system --uid 1000 --gid 1000 --home-dir /data --no-create-home --shell /usr/sbin/nologin respire \
    && mkdir -p /data \
    && chown respire:respire /data

COPY --from=builder /out/bin/respire-server /usr/local/bin/respire-server
COPY --from=builder /out/bin/core-notices /usr/share/doc/respire-core
COPY --from=builder /out/runtime /usr/local/lib
RUN ldconfig

ENV ONEMEMORY_DATA_DIR=/data

USER respire
WORKDIR /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8787/ready || exit 1

CMD ["respire-server", "serve", "--bind", "0.0.0.0:8787"]
