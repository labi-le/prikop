package main

import (
	"flag"
	"os"
	"prikop/internal/orchestrator"
	"prikop/internal/worker"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "worker" {
		strategy := os.Args[2]
		group := "all"
		if len(os.Args) > 3 {
			group = os.Args[3]
		}
		worker.RunWorkerMode(strategy, group)
	} else {
		var cfg orchestrator.Config
		flag.StringVar(&cfg.FakePath, "fake-path", "/app/fake", "Path to the directory with fake packet .bin files")
		flag.StringVar(&cfg.TargetsPath, "targets-path", "/app/targets", "Path to the directory with target lists")
		flag.Parse()
		orchestrator.Run(cfg)
	}
}
