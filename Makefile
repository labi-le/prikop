.PHONY: build run

build:
	docker build -t prikop:latest .

run: build
	docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock prikop:latest
