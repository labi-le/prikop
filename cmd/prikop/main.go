package main

import (
	"flag"
	"os"
	"prikop/internal/orchestrator"
	"prikop/internal/worker"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		strategy := os.Args[2]
		group := "general"
		if len(os.Args) > 3 {
			group = os.Args[3]
		}
		worker.RunWorkerMode(strategy, group)
	} else {
		var cfg orchestrator.Config
		flag.StringVar(&cfg.FakePath, "fake-path", "/app/fake", "Path to bins")
		flag.StringVar(&cfg.TargetsPath, "targets-path", "/app/targets", "Path to targets (deprecated but kept for compat)")
		flag.Parse()
		orchestrator.Run(cfg)
	}
}
