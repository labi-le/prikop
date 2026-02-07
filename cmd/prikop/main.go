package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"prikop/internal/orchestrator"
	"prikop/internal/worker"
	"syscall"
)

func main() {
	workerSocket := flag.String("worker-socket", "", "Run in worker server mode on specified socket path")

	var cfg orchestrator.Config
	flag.StringVar(&cfg.FakePath, "fake-path", "/app/fake", "Path to bins")
	flag.StringVar(&cfg.TargetsPath, "targets-path", "/app/targets", "Path to targets")

	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *workerSocket != "" {
		worker.RunWorkerServer(ctx, *workerSocket)
	} else {
		orchestrator.Run(cfg)
	}
}
