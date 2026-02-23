---
name: nfqws-ops
description: Practical operational commands for nfqws. Includes binary discovery, manual testing via Docker, and container debugging.
---

# NFQWS Operations

Direct commands for interacting with nfqws inside the project's Docker environment.

## 1. Binary Discovery
Check available flags and features of the compiled `nfqws` binary:
```bash
docker run --rm --entrypoint /bin/sh prikop:latest -c "nfqws --help"
```

## 2. Manual Strategy Test
Run a strategy manually in a container (requires `NET_ADMIN` for NFQUEUE):
```bash
docker run --rm -it --cap-add=NET_ADMIN prikop:latest nfqws --dpi-desync=fake --dpi-desync-fooling=badsum
```

## 3. Worker Debugging
If a worker is running, inspect its state:

**Check iptables rules:**
```bash
docker exec -it <container_name> iptables -t mangle -L -v -n
```

**Check active connections/queues:**
```bash
docker exec -it <container_name> cat /proc/net/netfilter/nf_queue
```

## 4. Project Cleanup
Stop all active workers and remove sockets:
```bash
docker ps -q --filter "name=prikop-worker" | xargs -r docker rm -f
rm -rf /tmp/prikop_sockets/*
```
