.PHONY: build run

run: build
	docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock prikop:latest

build:
	docker build -t prikop:latest .

context:
	./generate_context.sh . -e .idea > context.md