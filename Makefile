.PHONY: build run

CURRENT_DIR := $(shell pwd)

HOST_SOCKET_DIR ?= /tmp/prikop_sockets
HOST_TARGETS_DIR ?= $(CURRENT_DIR)/targets
PROVIDER ?=

run: build
	mkdir -p $(HOST_SOCKET_DIR)
	mkdir -p $(HOST_TARGETS_DIR)
	chmod 777 $(HOST_SOCKET_DIR)
	chmod 777 $(HOST_TARGETS_DIR)

	docker run --rm -it \
	   -v /var/run/docker.sock:/var/run/docker.sock \
	   -v $(HOST_SOCKET_DIR):/var/run/prikop \
	   -v $(HOST_TARGETS_DIR):/app/targets \
	   -v $(CURRENT_DIR)/fake:/app/fake \
	   -e HOST_SOCKET_DIR=$(HOST_SOCKET_DIR) \
	   -e HOST_TARGETS_DIR=$(HOST_TARGETS_DIR) \
	   prikop:latest $(if $(PROVIDER),-provider $(PROVIDER))

build: generate
	docker build -t prikop:latest .

context:
	./generate_context.sh . -e targets -e internal/verifier -e '*_test.go' > context.md

generate:
	go generate ./...