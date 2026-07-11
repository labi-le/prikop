ARG MIRROR_REGISTRY_PREFIX
ARG GO_VERSION=1.26

FROM ${MIRROR_REGISTRY_PREFIX}golang:${GO_VERSION} AS modules
ADD go.mod go.sum /m/
RUN cd /m && go mod download

FROM ${MIRROR_REGISTRY_PREFIX}debian:bookworm-slim AS nfqws-builder
RUN apt-get update && apt-get install -y \
    git make gcc libc6-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    zlib1g-dev \
    libcap-dev \
    libmnl-dev \
    libluajit-5.1-dev \
    pkg-config

WORKDIR /tmp
RUN git clone --depth 1 https://github.com/bol-van/zapret2.git \
    && make -C zapret2/nfq2
# produces zapret2/nfq2/nfqws2 ; lua libraries live in zapret2/lua/*.lua

FROM ${MIRROR_REGISTRY_PREFIX}golang:${GO_VERSION} AS builder
COPY --from=modules /go/pkg /go/pkg

RUN mkdir -p /app
COPY . /app
WORKDIR /app

RUN go build -tags netgo,osusergo \
    -ldflags '-extldflags "-static" -s -w' \
    -v -o prikop ./cmd/prikop

FROM ${MIRROR_REGISTRY_PREFIX}debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iptables \
    libnetfilter-queue1 \
    libnfnetlink0 \
    libmnl0 \
    libluajit-5.1-2 \
    libcap2-bin \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nfqws-builder /tmp/zapret2/nfq2/nfqws2 /usr/bin/nfqws2
COPY --from=nfqws-builder /tmp/zapret2/lua/ /app/lua/
COPY --from=builder /app/prikop /usr/bin/prikop

COPY --from=builder /app/fake /app/fake

RUN mkdir -p /app/targets && chmod 777 /app/targets

COPY --from=builder /app/targets /app/targets

RUN chmod +x /usr/bin/nfqws2 /usr/bin/prikop

ENTRYPOINT ["/usr/bin/prikop"]
