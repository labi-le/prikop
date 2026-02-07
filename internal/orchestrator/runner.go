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

	"github.com/moby/moby/client"
)

type Config struct {
	FakePath    string
	TargetsPath string
}

type Phase struct {
	Name    string
	Group   string
	Gens    int
	Filters string
}

var pool *container.WorkerPool

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

	pool = container.NewWorkerPool(ctx, cli, model.MaxWorkers, hostSockDir)

	if err := pool.Start(); err != nil {
		log.Fatalf("Worker pool start failed: %v", err)
	}
	defer func() {
		fmt.Println(">>> Cleaning up resources...")
		pool.Stop()
	}()

	fmt.Println(">>> RUNNING GLOBAL RECONNAISSANCE")
	report := recon.RunScout(ctx, pool, "google")
	if ctx.Err() != nil {
		return
	}
	fmt.Printf("Recon Report: %+v\n", report)

	discoveredBins, err := container.DiscoverBinFiles(ctx, cli, cfg.FakePath)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatalf("Failed to discover bins: %v", err)
	}
	fmt.Printf(">>> Found %d bin files\n", len(discoveredBins))

	phases := definePhases(cfg.TargetsPath)
	optimizer := NewOptimizer(pool)

	executePhases(ctx, optimizer, phases, discoveredBins, report)
}

func definePhases(targetsPath string) []Phase {
	return []Phase{
		{
			Name:    "GENERAL TCP (TCP 16-20 Checker)",
			Group:   "general",
			Gens:    8,
			Filters: "--filter-tcp=80,443",
		},
		{
			Name:    "GOOGLE TCP",
			Group:   "google_tcp",
			Gens:    5,
			Filters: fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", targetsPath),
		},
		{
			Name:    "GOOGLE UDP (QUIC)",
			Group:   "google_udp",
			Gens:    5,
			Filters: fmt.Sprintf("--filter-udp=443 --hostlist=%s/google.txt", targetsPath),
		},
		{
			Name:    "DISCORD UDP (Voice)",
			Group:   "discord_udp",
			Gens:    5,
			Filters: fmt.Sprintf("--filter-udp=50000-65535,443 --hostlist=%s/discord.txt", targetsPath),
		},
		{
			Name:    "DISCORD UDP (STUN)",
			Group:   "discord_l7",
			Gens:    5,
			Filters: fmt.Sprintf("--filter-udp=19294-19344 --filter-l7=discord,stun --hostlist=%s/discord.txt", targetsPath),
		},
	}
}

func executePhases(ctx context.Context, opt *Optimizer, phases []Phase, bins []string, report model.ReconReport) {
	var finalConfigs []string

	for _, p := range phases {
		// CHECKPOINT: Check before starting phase
		if ctx.Err() != nil {
			fmt.Println("\n>>> Process aborted by user.")
			return
		}

		fmt.Printf("\n>>> PHASE: %s\n", p.Name)
		fmt.Printf(">>> Filters: %s\n", p.Filters)

		best := opt.RunPhase(ctx, p.Group, bins, p.Gens, report)

		// Check cancellation return
		if ctx.Err() != nil {
			fmt.Println("\n>>> Process aborted by user.")
			return
		}

		if best != nil {
			strategyArgs := best.Config.ToArgs()
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
