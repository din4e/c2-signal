FROM node:22-bookworm-slim AS web-build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.24-bookworm AS api-build
WORKDIR /src
COPY backend/go.mod ./
COPY backend/ ./
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/scanner ./cmd/server

FROM rust:1.91-bookworm AS chainsaw-build
ARG CHAINSAW_VERSION=v2.16.0
RUN apt-get update && apt-get install -y --no-install-recommends git clang cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${CHAINSAW_VERSION}" https://github.com/WithSecureLabs/chainsaw.git .
RUN cargo build --release --locked && cp target/release/chainsaw /out-chainsaw

FROM rust:1.91-bookworm AS suricata-build
ARG SURICATA_VERSION=8.0.5
RUN apt-get update \
    && apt-get install -y --no-install-recommends autoconf automake build-essential cbindgen curl \
       libjansson-dev libpcap-dev libpcre2-dev libtool libyaml-dev make pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSLO "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
    && tar -xzf "suricata-${SURICATA_VERSION}.tar.gz" --strip-components=1 \
    && ./configure --prefix=/opt/suricata --sysconfdir=/opt/suricata/etc --localstatedir=/opt/suricata/var --disable-gccmarch-native \
    && make -j"$(nproc)"
RUN make install && make install-conf

FROM debian:bookworm-slim AS runtime
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="C2 Signal" \
      org.opencontainers.image.description="Multi-engine defensive artifact detection console" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl yara \
       libjansson4 libpcap0.8 libpcre2-8-0 libyaml-0-2 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --home-dir /nonexistent --shell /usr/sbin/nologin scanner \
    && mkdir -p /app/web /data/uploads /rules/yara /rules/sigma /rules/suricata /rules/mappings \
    && chown -R scanner:scanner /data /app

COPY --from=api-build /out/scanner /usr/local/bin/c2-scanner
COPY --from=chainsaw-build /out-chainsaw /usr/local/bin/chainsaw
COPY --from=chainsaw-build /src/mappings/sigma-event-logs-all.yml /rules/mappings/sigma-event-logs-all.yml
COPY --from=suricata-build /opt/suricata /opt/suricata
COPY --from=web-build /src/out/ /app/web/
COPY --chown=scanner:scanner rules/yara/ /rules/yara/local/
RUN chmod -R a+rX /opt/suricata

USER scanner:scanner
WORKDIR /app
EXPOSE 8080
ENV LISTEN_ADDR=:8080 WEB_ROOT=/app/web DATA_DIR=/data/uploads \
    HISTORY_DIR=/data/history HISTORY_LIMIT=200 \
    MANAGED_YARA_ROOT=/rules/yara/local \
    PATH=/opt/suricata/bin:${PATH} LD_LIBRARY_PATH=/opt/suricata/lib
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 CMD ["curl", "-fsS", "http://127.0.0.1:8080/api/v1/health"]
ENTRYPOINT ["/usr/local/bin/c2-scanner"]
