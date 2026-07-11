.PHONY: build run voice-test

CURRENT_DIR := $(shell pwd)

HOST_SOCKET_DIR ?= /tmp/prikop_sockets
HOST_TARGETS_DIR ?= $(CURRENT_DIR)/targets
PROVIDER ?=

NIX_RUN := nix-shell --run

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

# Voice check runs on the HOST (needs root + visibility of your real call), not
# in Docker: Discord's DAVE makes active probing impossible, so we sniff a call.
voice-test:
	$(NIX_RUN) "CGO_ENABLED=0 go build -o /tmp/prikop-voice ./cmd/prikop"
	@echo ">>> join a Discord voice call and TALK during the ~20s capture"
	sudo /tmp/prikop-voice -provider discord_voice

build: generate
	docker build -t prikop:latest .

context:
	./generate_context.sh . -e targets -e internal/verifier -e '*_test.go' > context.md

generate:
	$(NIX_RUN) "go generate ./..."