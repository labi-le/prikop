.PHONY: build run

HOST_SOCKET_DIR ?= /tmp/prikop_sockets

run: build
	mkdir -p $(HOST_SOCKET_DIR)
	chmod 777 $(HOST_SOCKET_DIR)
	docker run --rm -it \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(HOST_SOCKET_DIR):/var/run/prikop \
		-v ./fake:/app/fake \
		-e HOST_SOCKET_DIR=$(HOST_SOCKET_DIR) \
		prikop:latest


build:
	docker build -t prikop:latest .

context:
	./generate_context.sh . -e targets -e '*_test.go' > context.md