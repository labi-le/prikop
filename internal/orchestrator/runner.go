package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"prikop/internal/container"
	"prikop/internal/model"
	"prikop/internal/scout"
	"prikop/internal/verifier/availability"
	"prikop/internal/verifier/checker"
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
	Provider string
}

type config struct {
	Config   string
	Provider string
}

var pool *container.WorkerPool

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
	report := scout.RunScout(ctx, pool, log.With().Str("component", "recon").Logger())
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

	providers := tcp16_20.Cases()
	log.Info().Int("count", len(providers)).Msg("Initialized provider definitions")

	// STARTUP VALIDATION: Ensure all targets are within their CIDR ranges
	log.Info().Msg("Validating all provider targets against CIDRs...")
	var hasValidationErrors bool
	for _, p := range providers {
		if p.CIDRFile == "" {
			continue
		}
		networks, err := checker.LoadCIDRs(p.CIDRFile)
		if err != nil {
			log.Error().Err(err).Str("provider", p.Name).Str("cidr_file", p.CIDRFile).Msg("Failed to load CIDRs for startup validation")
			hasValidationErrors = true
			continue
		}

		for _, t := range p.Targets {
			if err := checker.ValidateIP(t.URL, networks); err != nil {
				log.Error().Err(err).Str("provider", p.Name).Str("url", t.URL).Msg("STARTUP VALIDATION FAILED: Target IP is not in CIDR range")
				hasValidationErrors = true
			}
		}
	}

	if hasValidationErrors {
		log.Fatal().Msg("Startup validation failed. Please fix the target lists or CIDR sources listed above.")
	}
	log.Info().Msg("Startup validation passed successfully")

	allProviders := append(availability.InitializeProviders(cfg.Provider), providers...)

	optimizer := NewOptimizer(pool, log.With().Str("component", "optimizer").Logger())
	runProviders(ctx, optimizer, allProviders, discoveredBins, report, log)
}

func runProviders(ctx context.Context, opt *Optimizer, providers []types.ProviderDefinition, bins []string, report model.ReconReport, log zerolog.Logger) {
	var mu sync.Mutex
	var finalConfigs []config

	sem := make(chan struct{}, model.MaxConcurrentProviders)
	var wg sync.WaitGroup

	for _, p := range providers {
		if ctx.Err() != nil {
			break
		}

		gens := p.Gens
		if gens == 0 {
			gens = 5
		}

		wg.Add(1)
		go func(p types.ProviderDefinition, gens int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			provLogger := log.With().Str("provider", p.Name).Logger()
			provLogger.Info().Msg("Executing provider")

			best := opt.RunPhase(ctx, p.Name, bins, gens, report, p.Filters)
			if ctx.Err() != nil {
				return
			}

			if best != nil && best.Result.SuccessCount > 0 && best.Result.SuccessCount*2 >= best.Result.TotalCount {
				strategyArgs := best.Config.String()
				provLogger.Info().Str("winner", strategyArgs).Msg("Provider finished with a winning strategy")
				block := fmt.Sprintf("%s %s", p.Filters, strategyArgs)

				mu.Lock()
				finalConfigs = append(finalConfigs, config{
					Config:   block,
					Provider: p.Name,
				})
				mu.Unlock()
			} else {
				provLogger.Warn().Msg("Provider failed: No working strategy found")
			}
		}(p, gens)
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
	fmt.Println()
}
