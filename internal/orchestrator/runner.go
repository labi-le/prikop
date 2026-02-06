package orchestrator

import (
	"context"
	"fmt"
	"log"
	"prikop/internal/container"
	"prikop/internal/genes"
	"prikop/internal/model"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moby/moby/client"
)

type Config struct {
	FakePath    string
	TargetsPath string
}

type Phase struct {
	Name        string
	TargetGroup string
	Filters     string
	MaxGens     int
	SuccessRate int // Percentage 0-100 required to stop early
}

var (
	discoveredBins []string
)

func Run(cfg Config) {
	ctx := context.Background()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Docker client failed: %v", err)
	}
	defer cli.Close()

	fmt.Println(">>> 🔎 Discovering .bin files inside the container...")
	bins, err := container.DiscoverBinFiles(ctx, cli, cfg.FakePath)
	if err != nil || len(bins) == 0 {
		log.Fatalf("❌ FATAL: Failed to discover bins or no bins found. Err: %v", err)
	}
	discoveredBins = bins
	fmt.Printf(">>> ✅ Found %d .bin files.\n", len(discoveredBins))

	// SPLIT PHASES FOR PROTOCOL ISOLATION
	// NOTE: Using model.MaxGenerations and model.TargetSuccessRate where applicable
	phases := []Phase{
		{
			Name:        "GOOGLE (TCP)",
			TargetGroup: "google_tcp",
			Filters:     fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", cfg.TargetsPath),
			MaxGens:     model.MaxGenerations,
			SuccessRate: model.TargetSuccessRate, // Pure TCP should hit high rate
		},
		{
			Name:        "GOOGLE (UDP/QUIC)",
			TargetGroup: "google_udp",
			Filters:     fmt.Sprintf("--filter-udp=443 --hostlist=%s/google.txt", cfg.TargetsPath),
			MaxGens:     20,
			SuccessRate: 80, // UDP is harder/flakier
		},
		{
			Name:        "DISCORD (TCP)",
			TargetGroup: "discord_tcp",
			Filters:     fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/discord.txt", cfg.TargetsPath),
			MaxGens:     20,
			SuccessRate: model.TargetSuccessRate,
		},
		{
			Name:        "DISCORD (UDP)",
			TargetGroup: "discord_udp",
			Filters:     fmt.Sprintf("--filter-udp=443,50000-65535 --hostlist=%s/discord.txt", cfg.TargetsPath),
			MaxGens:     20,
			SuccessRate: 90,
		},
		{
			Name:        "GENERAL",
			TargetGroup: "general",
			Filters:     "--filter-tcp=80,443", // Catch-all for remaining traffic
			MaxGens:     model.MaxGenerations,
			SuccessRate: 80,
		},
	}
	// ... (остальной код runner.go без изменений)
	var finalStrategies []string

	for _, p := range phases {
		fmt.Printf("\n>>> 🚀 STARTING PHASE: %s\n", p.Name)
		fmt.Printf(">>> 🛡️  Filters: %s\n", p.Filters)

		best := runEvolutionPhase(ctx, cli, p, cfg.FakePath)

		if best.Strategy != "" {
			// Clean up strategy string for final output
			// We combine the static filter with the evolved strategy
			final := fmt.Sprintf("%s %s", p.Filters, best.Strategy)
			finalStrategies = append(finalStrategies, final)
			fmt.Printf("\n>>> 🏆 PHASE %s WINNER: %s\n", p.Name, final)
		} else {
			fmt.Printf("\n>>> ⚠️  PHASE %s FAILED (No working strategy found)\n", p.Name)
		}
	}

	fmt.Println("\n=======================================================")
	fmt.Println(">>> 🎉 FINAL CONFIGURATION (Combine with --new)")
	fmt.Println("=======================================================")

	printFinalConfig(finalStrategies)
}

func printFinalConfig(strats []string) {
	if len(strats) == 0 {
		fmt.Println("# No working strategies found.")
		return
	}

	fmt.Println(strings.Join(strats, " --new "))
}

func runEvolutionPhase(ctx context.Context, cli *client.Client, p Phase, fakePath string) model.StrategyResult {
	history := make(map[string]bool)
	var globalBest model.StrategyResult
	totalAttempts := 0

	currentGenStrats := genes.GenerateInitialPopulation(model.PopulationSize, discoveredBins, fakePath)

	for gen := 0; gen < p.MaxGens; gen++ {
		fmt.Printf("\n>>> 🧬 [%s] GEN %d/%d (%d strategies)\n", p.Name, gen, p.MaxGens, len(currentGenStrats))

		results, _ := executeBatch(ctx, cli, currentGenStrats, p.Filters, p.TargetGroup, history, &totalAttempts, &globalBest)

		// Check for elite survivor
		if len(results) > 0 {
			genBest := results[0]
			if genBest.SuccessCount > globalBest.SuccessCount ||
				(genBest.SuccessCount == globalBest.SuccessCount && genBest.Duration < globalBest.Duration) {
				globalBest = genBest
				fmt.Printf(">>> 🏆 [%s] NEW BEST: [%d/%d] %s\n", p.Name, globalBest.SuccessCount, globalBest.TotalCount, globalBest.Strategy)
			}
		}

		// Calculate Success Percentage
		successPct := 0
		if globalBest.TotalCount > 0 {
			successPct = (globalBest.SuccessCount * 100) / globalBest.TotalCount
		}

		if successPct >= p.SuccessRate {
			fmt.Printf("\n>>> ✅ [%s] Target Success Rate (%d%%) Achieved!\n", p.Name, p.SuccessRate)
			break
		}

		// Selection
		var survivors []model.StrategyResult
		if globalBest.Strategy != "" {
			survivors = append(survivors, globalBest)
		}
		// Pick top elites
		for i := 0; i < len(results) && len(survivors) < model.ElitesCount+1; i++ {
			if results[i].Strategy != globalBest.Strategy {
				survivors = append(survivors, results[i])
			}
		}

		if len(survivors) == 0 {
			fmt.Println("\033[33m>>> Gen failed. Injecting chaos.\033[0m")
			currentGenStrats = genes.GenerateChaosPopulation(model.PopulationSize, discoveredBins)
			continue
		}

		currentGenStrats = genes.BreedingProtocol(survivors, model.PopulationSize, discoveredBins)
	}

	return globalBest
}

func executeBatch(
	ctx context.Context,
	cli *client.Client,
	genesList []string,
	filterPrefix string,
	targetGroup string,
	history map[string]bool,
	counter *int,
	currentBest *model.StrategyResult,
) ([]model.StrategyResult, int) {

	resultsCh := make(chan model.StrategyResult, len(genesList))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, model.MaxWorkers)
	var results []model.StrategyResult

	startBatch := time.Now()
	processedInBatch := 0

	var validGenes []string
	for _, g := range genesList {
		g = strings.TrimSpace(strings.ReplaceAll(g, "  ", " "))
		if !history[g] && *counter < model.MaxTotalAttempts {
			validGenes = append(validGenes, g)
			history[g] = true
			*counter++
		}
	}

	totalInBatch := len(validGenes)
	// Track the actual BEST SCORE seen in this specific run so far to control logging
	var bestScoreSoFar int32 = int32(currentBest.SuccessCount)

	go func() {
		for {
			if processedInBatch >= totalInBatch {
				break
			}
			curBest := atomic.LoadInt32(&bestScoreSoFar)
			fmt.Printf("\r\033[K>>> ⏳ Processing: %d/%d (High Score: %d)", processedInBatch, totalInBatch, curBest)
			time.Sleep(500 * time.Millisecond)
		}
	}()

	for _, gene := range validGenes {
		wg.Add(1)
		go func(g string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			workerCtx, cancel := context.WithTimeout(ctx, model.ContainerTimeout)
			defer cancel()

			fullStrategy := fmt.Sprintf("%s %s", filterPrefix, g)

			start := time.Now()
			res, sysLogs := container.RunContainerTest(workerCtx, cli, fullStrategy, targetGroup)
			dur := time.Since(start)

			sr := model.StrategyResult{
				Strategy:     g,
				Duration:     dur,
				WorkerResult: res,
				SystemLogs:   sysLogs,
			}

			// Atomic check and update for logging
			oldBest := atomic.LoadInt32(&bestScoreSoFar)
			isNewBest := false
			isEqualBest := false

			if int32(res.SuccessCount) > oldBest {
				// Try to swap. If failed, it means someone else updated it, so we are not the strictly new best locally anymore
				if atomic.CompareAndSwapInt32(&bestScoreSoFar, oldBest, int32(res.SuccessCount)) {
					isNewBest = true
				}
				// Reload to be sure
				oldBest = atomic.LoadInt32(&bestScoreSoFar)
			}

			if !isNewBest && int32(res.SuccessCount) == oldBest && oldBest > 0 {
				isEqualBest = true
			}

			// Display logic
			if res.Success {
				if isNewBest {
					// Strictly NEW high score
					fmt.Printf("\r\033[K\033[32;1m🔥 [%.1fs] [%d/%d] %s\033[0m\n", dur.Seconds(), res.SuccessCount, res.TotalCount, g)
				} else if isEqualBest {
					// Equal to high score, but not new
					fmt.Printf("\r\033[K\033[37m⭐ [%.1fs] [%d/%d] %s\033[0m\n", dur.Seconds(), res.SuccessCount, res.TotalCount, g)
				}
				// Don't print if it's worse than current best (reduce noise)
			}

			resultsCh <- sr
			processedInBatch++
		}(gene)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	for res := range resultsCh {
		if res.Success {
			results = append(results, res)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].SuccessCount != results[j].SuccessCount {
			return results[i].SuccessCount > results[j].SuccessCount
		}
		return results[i].Duration < results[j].Duration
	})

	fmt.Printf("\r\033[K>>> Batch finished in %.2fs. Found %d working.\n", time.Since(startBatch).Seconds(), len(results))
	return results, processedInBatch
}
