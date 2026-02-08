package orchestrator

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"prikop/internal/container"
	"prikop/internal/model"
	"prikop/internal/recon"
	"prikop/internal/verifier"

	"github.com/moby/moby/client"
)

type Config struct {
	FakePath string
}

type Phase struct {
	Name    string
	Group   string
	Gens    int
	Filters string
}

var pool *container.WorkerPool

const HostListPath = "/app/targets"

func Run(cfg Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Error creating docker client: %v", err)
	}
	defer cli.Close()

	hostSockDir := os.Getenv("HOST_SOCKET_DIR")
	if hostSockDir == "" {
		hostSockDir = "/tmp/prikop_sockets"
	}

	hostTargetsDir := os.Getenv("HOST_TARGETS_DIR")
	if hostTargetsDir == "" {
		hostTargetsDir = "/tmp/prikop_targets"
		_ = os.MkdirAll(hostTargetsDir, 0777)
	}

	pool = container.NewWorkerPool(ctx, cli, model.MaxWorkers, hostSockDir, hostTargetsDir)

	if err := pool.Start(); err != nil {
		log.Fatalf("Worker pool start failed: %v", err)
	}
	defer func() {
		fmt.Println(">>> Cleaning up resources...")
		pool.Stop()
	}()

	fmt.Println(">>> RUNNING GLOBAL RECONNAISSANCE")
	report := recon.RunScout(ctx, pool, "google_tcp")
	if ctx.Err() != nil {
		return
	}
	fmt.Printf("Recon Report: %+v\n", report)

	discoveredBins, err := container.DiscoverBinFiles(cfg.FakePath)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatalf("Failed to discover bins: %v", err)
	}
	fmt.Printf(">>> Found %d bin files\n", len(discoveredBins))

	// Load providers using static definitions
	providers, err := verifier.InitializeProviders(true)
	if err != nil {
		fmt.Printf("Warning: failed to initialize providers: %v\n", err)
	}
	fmt.Printf(">>> Initialized %d providers definitions\n", len(providers))

	phases := definePhases(providers)
	optimizer := NewOptimizer(pool)

	executePhases(ctx, optimizer, phases, discoveredBins, report)
}

func definePhases(providers []verifier.ProviderDefinition) []Phase {
	var phases []Phase

	// 1. Core Phases
	phases = append(phases, Phase{
		Name:    "GOOGLE TCP",
		Group:   "google_tcp",
		Gens:    5,
		Filters: fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", HostListPath),
	})

	//// FIX: Add strict L7 filter to avoid processing Torrent DHT garbage
	phases = append(phases, Phase{
		Name:    "GOOGLE UDP (QUIC)",
		Group:   "google_udp",
		Gens:    5,
		Filters: fmt.Sprintf("--filter-udp=443 --filter-l7=quic --hostlist=%s/google.txt", HostListPath),
	})

	// 2. Dynamic Provider Phases
	for _, p := range providers {
		filters := "--filter-tcp=80,443"

		if p.CIDRFile != "" {
			filters += fmt.Sprintf(" --ipset=%s", p.CIDRFile)
		} else {
			fmt.Printf("Warning: Provider %s has no CIDR file, skipping specific filters\n", p.Name)
		}

		// Fallback/Default for missing Gens in existing/new definitions
		gens := p.Gens
		if gens == 0 {
			gens = 5
		}

		phases = append(phases, Phase{
			Name:    fmt.Sprintf("PROVIDER: %s", strings.ToUpper(p.Name)),
			Group:   p.Name,
			Gens:    gens,
			Filters: filters,
		})
	}

	return phases
}

func executePhases(ctx context.Context, opt *Optimizer, phases []Phase, bins []string, report model.ReconReport) {
	var finalConfigs []string

	for _, p := range phases {
		if ctx.Err() != nil {
			return
		}

		fmt.Printf("\n>>> PHASE: %s\n", p.Name)

		best := opt.RunPhase(ctx, p.Group, bins, p.Gens, report, p.Filters)
		if ctx.Err() != nil {
			return
		}

		if best != nil && best.Result.SuccessCount > 0 {
			strategyArgs := best.Config.String()
			fmt.Printf(">>> WINNER: %s\n", strategyArgs)
			block := fmt.Sprintf("%s %s", p.Filters, strategyArgs)
			finalConfigs = append(finalConfigs, block)
		} else {
			fmt.Printf(">>> FAILED: No working strategy found for %s\n", p.Name)
		}
	}

	printFinalConfig(finalConfigs)
}

func printFinalConfig(configs []string) {
	fmt.Println("\n=======================================================")
	fmt.Println(">>> 🎉 FINAL CONFIGURATION")
	fmt.Println("=======================================================")

	if len(configs) == 0 {
		fmt.Println("# No working strategies found.")
		return
	}

	finalStr := strings.Join(configs, "\n--new\n")
	fmt.Println(finalStr)
	fmt.Println("\n=======================================================")
}
