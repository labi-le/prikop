package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"prikop/internal/container"
	"prikop/internal/model"
	"prikop/internal/recon"
	"prikop/internal/verifier/tcp16_20"
	"prikop/internal/verifier/types"
	"strings"
	"sync"
	"syscall"

	"github.com/moby/moby/client"
	"github.com/rs/zerolog"
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

type config struct {
	Config   string
	Provider string
}

var pool *container.WorkerPool

const HostListPath = "/app/targets"

func Run(cfg Config, log zerolog.Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating docker client")
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

	pool = container.NewWorkerPool(ctx, cli, model.MaxWorkers, hostSockDir, hostTargetsDir, log.With().Str("component", "workerpool").Logger())

	if err := pool.Start(); err != nil {
		log.Fatal().Err(err).Msg("Worker pool start failed")
	}
	defer func() {
		pool.Stop()
	}()

	log.Info().Msg("Running global reconnaissance")
	report := recon.RunScout(ctx, pool, "google_tcp", log.With().Str("component", "recon").Logger())
	if ctx.Err() != nil {
		return
	}
	log.Info().Interface("report", report).Msg("Recon Report")

	discoveredBins, err := container.DiscoverBinFiles(cfg.FakePath)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatal().Err(err).Msg("Failed to discover bins")
	}
	log.Info().Int("count", len(discoveredBins)).Msg("Discovered bin files")

	providers, err := tcp16_20.InitializeProviders(true, log.With().Str("component", "verifier").Logger())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize providers")
	}
	log.Info().Int("count", len(providers)).Msg("Initialized provider definitions")

	phases := definePhases(providers, log)
	optimizer := NewOptimizer(pool, log.With().Str("component", "optimizer").Logger())

	executePhases(ctx, optimizer, phases, discoveredBins, report, log)
}

func definePhases(providers []types.ProviderDefinition, log zerolog.Logger) []Phase {
	var phases []Phase

	phases = append(phases, Phase{
		Name:    "GOOGLE TCP",
		Group:   "google_tcp",
		Gens:    10,
		Filters: fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", HostListPath),
	})

	// phases = append(phases, Phase{
	// 	Name:    "GOOGLE UDP (QUIC)",
	// 	Group:   "google_udp",
	// 	Gens:    10,
	// 	Filters: fmt.Sprintf("--filter-udp=443 --filter-l7=quic --hostlist=%s/google.txt", HostListPath),
	// })

	for _, p := range providers {
		filters := "--filter-tcp=80,443"

		if p.CIDRFile != "" {
			filters += fmt.Sprintf(" --ipset=%s", p.CIDRFile)
		} else {
			log.Info().Str("provider", p.Name).Msg("Provider has no CIDR file, applying global filter (all traffic)")
		}

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

func executePhases(ctx context.Context, opt *Optimizer, phases []Phase, bins []string, report model.ReconReport, log zerolog.Logger) {
	var mu sync.Mutex
	var finalConfigs []config

	sem := make(chan struct{}, model.MaxConcurrentProviders)
	var wg sync.WaitGroup

	for _, p := range phases {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(p Phase) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			phaseLogger := log.With().Str("phase", p.Name).Logger()
			phaseLogger.Info().Msg("Executing phase")

			best := opt.RunPhase(ctx, p.Group, bins, p.Gens, report, p.Filters)
			if ctx.Err() != nil {
				return
			}

			if best != nil && best.Result.SuccessCount > 0 && best.Result.SuccessCount*2 >= best.Result.TotalCount {
				strategyArgs := best.Config.String()
				phaseLogger.Info().Str("winner", strategyArgs).Msg("Phase finished with a winning strategy")
				block := fmt.Sprintf("%s %s", p.Filters, strategyArgs)

				mu.Lock()
				finalConfigs = append(finalConfigs, config{
					Config:   block,
					Provider: p.Name,
				})
				mu.Unlock()
			} else {
				phaseLogger.Warn().Msg("Phase failed: No working strategy found")
			}
		}(p)
	}

	wg.Wait()
	printFinalConfig(finalConfigs)
}

func printFinalConfig(configsWithProvider []config) {
	fmt.Println(">>> 🎉 FINAL CONFIGURATION")
	fmt.Println()

	if len(configsWithProvider) == 0 {
		fmt.Println("# No working strategies found.")
		return
	}

	var outputLines []string
	for i, configWithProvider := range configsWithProvider {
		commentLine := fmt.Sprintf("# %d: %s", i+1, configWithProvider.Provider)
		outputLines = append(outputLines, commentLine)

		args := strings.Fields(configWithProvider.Config)
		for _, arg := range args {
			outputLines = append(outputLines, arg)
		}

		if i < len(configsWithProvider)-1 {
			outputLines = append(outputLines, "--new")
		}
	}

	finalStr := strings.Join(outputLines, "\n")
	fmt.Println(finalStr)
}
