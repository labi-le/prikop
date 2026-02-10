package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"prikop/internal/orchestrator"
	"prikop/internal/worker"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

func main() {
	workerSocket := flag.String("worker-socket", "", "Run in worker server mode on specified socket path")

	var cfg orchestrator.Config
	flag.StringVar(&cfg.FakePath, "fake-path", "/app/fake", "Path to bins")

	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *workerSocket != "" {
		log := zerolog.New(os.Stderr).With().Timestamp().Logger()
		worker.RunWorkerServer(ctx, *workerSocket, log)
	} else {
		output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.Kitchen}
		log := zerolog.New(output).With().Timestamp().Logger()
		orchestrator.Run(cfg, log)
	}
}
