package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"prikop/internal/container"
	"prikop/internal/model"
	"prikop/internal/nfqws2"
	"prikop/internal/scout"
	"prikop/internal/verifier/availability"
	"prikop/internal/verifier/checker"
	"prikop/internal/verifier/tcp16_20"
	"prikop/internal/verifier/types"
	"sort"
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
	Strategy string
	Filters  []string
	Provider []string
}

func (c *config) FullConfig() string {
	return fmt.Sprintf("%s %s", strings.Join(c.Filters, " "), c.Strategy)
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

var (
	globalBestTCP *nfqws2.Strategy
	globalBestUDP *nfqws2.Strategy
	globalMu      sync.Mutex
)

func runProviders(ctx context.Context, opt *Optimizer, providers []types.ProviderDefinition, bins []string, report model.ReconReport, log zerolog.Logger) {
	var mu sync.Mutex
	var rawConfigs []struct {
		Strategy string
		Filters  string
		Provider string
	}

	sem := make(chan struct{}, model.MaxConcurrentProviders)
	var wg sync.WaitGroup

	for _, p := range providers {
		if ctx.Err() != nil {
			break
		}

		if p.Gens == 0 {
			p.Gens = 3
		}

		wg.Add(1)
		go func(p types.ProviderDefinition) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			// Determine which global seed to use
			var seed *nfqws2.Strategy
			globalMu.Lock()
			if p.Proto == "udp" {
				seed = globalBestUDP
			} else {
				seed = globalBestTCP
			}
			globalMu.Unlock()

			provLogger := log.With().Str("provider", p.Name).Logger()
			provLogger.Info().Msg("Executing provider")

			best := opt.RunPhase(ctx, p, bins, report, seed)
			if ctx.Err() != nil {
				return
			}

			if best != nil && best.Result.SuccessCount > 0 && float64(best.Result.SuccessCount)/float64(best.Result.TotalCount) >= 0.5 {
				strategyArgs := best.Config.String()
				provLogger.Info().Str("winner", strategyArgs).Msg("Provider finished with a winning strategy")

				// Try to cast back to Strategy to update global best
				if s, ok := best.Config.(nfqws2.Strategy); ok {
					globalMu.Lock()
					if p.Proto == "udp" {
						if globalBestUDP == nil {
							globalBestUDP = &s
						}
					} else {
						if globalBestTCP == nil {
							globalBestTCP = &s
						}
					}
					globalMu.Unlock()
				}

				mu.Lock()
				rawConfigs = append(rawConfigs, struct {
					Strategy string
					Filters  string
					Provider string
				}{
					Strategy: strategyArgs,
					Filters:  p.Filters,
					Provider: p.Name,
				})
				mu.Unlock()
			} else {
				provLogger.Warn().Msg("Provider failed: No working strategy found")
			}
		}(p)
	}

	wg.Wait()

	finalConfigs := optimizeStrategies(rawConfigs)
	printFinalConfig(finalConfigs)
}

// optimizeStrategies merges duplicate strategies across providers
func optimizeStrategies(raw []struct {
	Strategy string
	Filters  string
	Provider string
}) []config {
	if len(raw) == 0 {
		return nil
	}

	// Group by Strategy
	groups := make(map[string]*config)
	for _, r := range raw {
		if c, ok := groups[r.Strategy]; ok {
			c.Provider = append(c.Provider, r.Provider)
			if r.Filters != "" {
				// Deduplicate filters
				found := false
				for _, existing := range c.Filters {
					if existing == r.Filters {
						found = true
						break
					}
				}
				if !found {
					c.Filters = append(c.Filters, r.Filters)
				}
			}
		} else {
			filters := []string{}
			if r.Filters != "" {
				filters = append(filters, r.Filters)
			}
			groups[r.Strategy] = &config{
				Strategy: r.Strategy,
				Filters:  filters,
				Provider: []string{r.Provider},
			}
		}
	}

	var result []config
	for _, c := range groups {
		result = append(result, *c)
	}

	// Sort for consistent output
	sort.Slice(result, func(i, j int) bool {
		return strings.Join(result[i].Provider, ",") < strings.Join(result[j].Provider, ",")
	})

	return result
}

func printFinalConfig(configs []config) {
	fmt.Println(">>> 🎉 FINAL CONFIGURATION")
	fmt.Println()

	if len(configs) == 0 {
		fmt.Println("# No working strategies found.")
		return
	}

	for i, c := range configs {
		fmt.Printf("# %d: %s\n", i+1, strings.Join(c.Provider, ", "))

		// Print filters
		for _, f := range c.Filters {
			fmt.Println(f)
		}

		// Print strategy
		fmt.Println(c.Strategy)

		if i < len(configs)-1 {
			fmt.Println("--new")
		}
	}
	fmt.Println()
}
