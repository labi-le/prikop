package main

import (
	"flag"
	"prikop/internal/orchestrator"
	"prikop/internal/worker"
)

func main() {
	workerSocket := flag.String("worker-socket", "", "Run in worker server mode on specified socket path")

	var cfg orchestrator.Config
	flag.StringVar(&cfg.FakePath, "fake-path", "/app/fake", "Path to bins")
	flag.StringVar(&cfg.TargetsPath, "targets-path", "/app/targets", "Path to targets")

	flag.Parse()

	if *workerSocket != "" {
		worker.RunWorkerServer(*workerSocket)
	} else {
		orchestrator.Run(cfg)
	}
}
