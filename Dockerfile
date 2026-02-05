ARG MIRROR_REGISTRY_PREFIX
ARG GO_VERSION=1.25

FROM ${MIRROR_REGISTRY_PREFIX}golang:${GO_VERSION} as modules
ADD go.mod go.sum /m/
RUN cd /m && go mod download

FROM ${MIRROR_REGISTRY_PREFIX}debian:bookworm-slim as downloader
RUN apt-get update && apt-get install -y curl ca-certificates
WORKDIR /tmp

RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) ZARCH="x86_64" ;; \
        aarch64) ZARCH="aarch64" ;; \
        armv7l) ZARCH="arm" ;; \
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac && \
    echo "Downloading nfqws for $ZARCH..." && \
    curl -L -o nfqws "https://github.com/bol-van/zapret/raw/master/binaries/$ZARCH/nfqws" && \
    chmod +x nfqws

FROM ${MIRROR_REGISTRY_PREFIX}golang:${GO_VERSION} as builder
COPY --from=modules /go/pkg /go/pkg

RUN mkdir -p /app
COPY . /app
WORKDIR /app

RUN go build -tags netgo,osusergo \
    -ldflags '-extldflags "-static" -s -w' \
    -v -o prikop main.go

FROM ${MIRROR_REGISTRY_PREFIX}debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    libnetfilter-queue1 \
    libnfnetlink0 \
    libcap2-bin \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=downloader /tmp/nfqws /usr/bin/nfqws
COPY --from=builder /app/prikop /usr/bin/prikop

ENTRYPOINT ["/usr/bin/prikop"]