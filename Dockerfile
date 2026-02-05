ARG MIRROR_REGISTRY_PREFIX
ARG GO_VERSION=1.25

FROM ${MIRROR_REGISTRY_PREFIX}golang:${GO_VERSION} as modules
ADD go.mod go.sum /m/
RUN cd /m && go mod download

FROM ${MIRROR_REGISTRY_PREFIX}debian:bookworm-slim as nfqws-builder
RUN apt-get update && apt-get install -y \
    git make gcc libc6-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    zlib1g-dev \
    libcap-dev \
    libmnl-dev

WORKDIR /tmp
RUN git clone --depth 1 https://github.com/bol-van/zapret.git \
    && cd zapret/nfq \
    && make

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

COPY --from=nfqws-builder /tmp/zapret/nfq/nfqws /usr/bin/nfqws
COPY --from=builder /app/prikop /usr/bin/prikop

COPY --from=builder /app/*.bin /app/

RUN chmod +x /usr/bin/nfqws /usr/bin/prikop

ENTRYPOINT ["/usr/bin/prikop"]