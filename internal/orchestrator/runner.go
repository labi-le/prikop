package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"prikop/internal/container"
	"prikop/internal/model"
	"prikop/internal/nfqws2"
	"prikop/internal/scout"
	"prikop/internal/verifier/availability"
	"prikop/internal/verifier/checker"
	"prikop/internal/verifier/tcp16_20"
	"prikop/internal/verifier/types"
	"prikop/internal/voicecap"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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

	// discord_voice is a host-level, root-gated PASSIVE voice check: Discord's
	// mandatory DAVE (E2EE) makes an active/bot probe impossible, so we sniff a
	// real call instead. It uses neither the Docker pool nor the GA — handle it
	// up front and return.
	if cfg.Provider == voiceProvider {
		runVoiceCapture(ctx, log)
		return
	}

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

	// All providers = availability (google/discord/nixos) + the generated
	// tcp16_20 suite. -provider narrows to one across BOTH sets; previously it
	// filtered only the availability set, so the tcp16_20 cases always ran.
	allProviders := append(availability.InitializeProviders(""), tcp16_20.Cases()...)
	if cfg.Provider != "" {
		var sel []types.ProviderDefinition
		for _, p := range allProviders {
			if p.Name == cfg.Provider {
				sel = append(sel, p)
			}
		}
		if len(sel) == 0 {
			log.Fatal().Str("provider", cfg.Provider).Msg("Unknown -provider")
		}
		allProviders = sel
	}
	log.Info().Int("count", len(allProviders)).Msg("Initialized provider definitions")

	// STARTUP VALIDATION: Ensure all targets are within their CIDR ranges
	log.Info().Msg("Validating all provider targets against CIDRs...")
	var hasValidationErrors bool
	for _, p := range allProviders {
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

	optimizer := NewOptimizer(pool, log.With().Str("component", "optimizer").Logger())
	runProviders(ctx, optimizer, allProviders, discoveredBins, report, log)
}

const voiceProvider = "discord_voice"

// runVoiceCapture verifies Discord voice by sniffing a live call (see package
// voicecap for why active probing is impossible). Needs root + tcpdump; if
// either is missing it skips rather than failing.
func runVoiceCapture(ctx context.Context, log zerolog.Logger) {
	vlog := log.With().Str("provider", voiceProvider).Logger()
	if os.Geteuid() != 0 {
		vlog.Warn().Msg("skipping: packet capture needs root (run: sudo prikop -provider discord_voice)")
		return
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		vlog.Warn().Msg("skipping: tcpdump not found in PATH")
		return
	}
	iface := voicecap.DefaultIface()
	const window = 20 * time.Second
	vlog.Info().Str("iface", iface).Dur("window", window).Msg("capturing Discord voice UDP — join a call and talk")

	res, err := voicecap.Capture(ctx, iface, window)
	if err != nil {
		vlog.Error().Err(err).Msg("voice capture failed")
		return
	}
	if len(res.Flows) == 0 {
		vlog.Warn().Msg("no Discord voice traffic seen — are you in a call? (or wrong interface)")
		return
	}
	for i, f := range res.Flows {
		if i >= 5 {
			break
		}
		vlog.Info().Str("server", f.Server).
			Int("out_pkts", f.OutPkts).Int("out_bytes", f.OutBytes).
			Int("in_pkts", f.InPkts).Int("in_bytes", f.InBytes).
			Bool("bidirectional", f.InPkts > 0).Msg("voice flow")
	}
	top := res.Flows[0]
	if res.Bidirectional {
		vlog.Info().Str("server", top.Server).Msg("PASS: Discord voice UDP is bidirectional — it crosses the DPI")
	} else {
		vlog.Warn().Str("server", top.Server).Msg("FAIL: top flow is outbound-only — voice UDP blocked by the DPI")
	}
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
