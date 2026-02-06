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
	Name              string
	TargetGroup       string
	Filters           string
	MaxGens           int
	SuccessRate       int
	InitialStrategies []string
}

var (
	discoveredBins []string
	printMu        sync.Mutex
)

func safePrintf(format string, a ...interface{}) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Print("\r\033[K")
	fmt.Printf(format, a...)
}

func safeProgress(format string, a ...interface{}) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Print("\r\033[K")
	fmt.Printf(format, a...)
}

// getDiscordStrategies returns heavy-hitters optimized for Discord voice/gateway
func getDiscordStrategies() []string {
	return []string{
		"--dpi-desync=multisplit --dpi-desync-split-seqovl=652 --dpi-desync-split-pos=2 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
		"--dpi-desync=fake,multisplit --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=1000 --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=multisplit --dpi-desync-split-pos=2,sniext+1 --dpi-desync-split-seqovl=679 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=10000000 --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
		"--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
	}
}

// getGoogleStrategies returns lighter strategies often effective for GGC
func getGoogleStrategies() []string {
	return []string{
		"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=none",
		"--dpi-desync=fake --dpi-desync-fake-tls-mod=none --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2",
		"--dpi-desync=fake,fakedsplit --dpi-desync-split-pos=1 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2 --dpi-desync-repeats=8 --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
		"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=badseq --dpi-desync-badseq-increment=2 --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fakedsplit-pattern=0x00 --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin",
		"--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=badseq --dpi-desync-fake-tls=0x00000000 --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
		"--dpi-desync=fake,hostfakesplit --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --dpi-desync-hostfakesplit-mod=host=www.google.com,altorder=1 --dpi-desync-fooling=ts",
		"--dpi-desync=hostfakesplit --dpi-desync-repeats=4 --dpi-desync-fooling=ts --dpi-desync-hostfakesplit-mod=host=www.google.com",
	}
}

func Run(cfg Config) {
	ctx := context.Background()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Docker client failed: %v", err)
	}
	defer cli.Close()

	safePrintf(">>> 🔎 Discovering .bin files inside the container...\n")
	bins, err := container.DiscoverBinFiles(ctx, cli, cfg.FakePath)
	if err != nil || len(bins) == 0 {
		log.Fatalf("❌ FATAL: Failed to discover bins or no bins found. Err: %v", err)
	}
	discoveredBins = bins
	safePrintf(">>> ✅ Found %d .bin files.\n", len(discoveredBins))

	phases := []Phase{
		{
			Name:              "GOOGLE (TCP)",
			TargetGroup:       "google_tcp",
			Filters:           fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", cfg.TargetsPath),
			MaxGens:           15,
			SuccessRate:       66,
			InitialStrategies: getGoogleStrategies(),
		},
		{
			Name:              "GOOGLE (UDP/QUIC)",
			TargetGroup:       "google_udp",
			Filters:           fmt.Sprintf("--filter-udp=443 --hostlist=%s/google.txt", cfg.TargetsPath),
			SuccessRate:       66,
			MaxGens:           20,
			InitialStrategies: getGoogleStrategies(),
		},
		{
			Name:              "DISCORD (TCP)",
			TargetGroup:       "discord_tcp",
			Filters:           fmt.Sprintf("--filter-tcp=80,443,2053,2083,2087,2096,8443 --hostlist=%s/discord.txt", cfg.TargetsPath),
			MaxGens:           15,
			SuccessRate:       model.TargetSuccessRate,
			InitialStrategies: getDiscordStrategies(),
		},
		{
			Name:              "DISCORD (UDP)",
			TargetGroup:       "discord_udp",
			Filters:           fmt.Sprintf("--filter-udp=443,19000-65535 --hostlist=%s/discord.txt", cfg.TargetsPath),
			MaxGens:           20,
			SuccessRate:       90,
			InitialStrategies: getDiscordStrategies(),
		},
		{
			Name:        "GENERAL",
			TargetGroup: "general",
			Filters:     "--filter-tcp=80,443",
			MaxGens:     model.MaxGenerations,
			SuccessRate: 80,
			// No explicit heavy strategies for general, rely on defaults/chaos
			InitialStrategies: nil,
		},
	}

	var finalStrategies []string

	for _, p := range phases {
		safePrintf("\n>>> 🚀 STARTING PHASE: %s\n", p.Name)
		safePrintf(">>> 🛡️  Filters: %s\n", p.Filters)

		if p.MaxGens == 0 {
			p.MaxGens = model.MaxGenerations
		}

		best := runEvolutionPhase(ctx, cli, p, cfg.FakePath)

		if best.Strategy != "" {
			final := fmt.Sprintf("%s %s", p.Filters, best.Strategy)
			finalStrategies = append(finalStrategies, final)
			safePrintf("\n>>> 🏆 PHASE %s WINNER: %s\n", p.Name, final)
		} else {
			safePrintf("\n>>> ⚠️  PHASE %s FAILED (No working strategy found)\n", p.Name)
		}
	}

	safePrintf("\n=======================================================\n")
	safePrintf(">>> 🎉 FINAL CONFIGURATION (Combine with --new)\n")
	safePrintf("=======================================================\n")

	printFinalConfig(finalStrategies)
}

func printFinalConfig(strats []string) {
	if len(strats) == 0 {
		safePrintf("# No working strategies found.\n")
		return
	}
	safePrintf("%s\n", strings.Join(strats, " --new "))
}

func runEvolutionPhase(ctx context.Context, cli *client.Client, p Phase, fakePath string) model.StrategyResult {
	history := make(map[string]bool)
	var globalBest model.StrategyResult
	totalAttempts := 0

	// Pass explicit InitialStrategies defined in the Phase struct
	currentGenStrats := genes.GenerateInitialPopulation(model.PopulationSize, discoveredBins, fakePath, p.InitialStrategies)

	for gen := 0; gen < p.MaxGens; gen++ {
		safePrintf("\n>>> 🧬 [%s] GEN %d/%d (%d strategies)\n", p.Name, gen, p.MaxGens, len(currentGenStrats))

		results, _ := executeBatch(ctx, cli, currentGenStrats, p.Filters, p.TargetGroup, history, &totalAttempts, &globalBest)

		if len(results) > 0 {
			genBest := results[0]

			// Logic to update global best
			isBetter := false

			if globalBest.TotalCount == 0 {
				isBetter = true
			} else {
				// Calculate weighted scores
				gBestScore := calculateWeightedScore(globalBest)
				genBestScore := calculateWeightedScore(genBest)

				if genBestScore > gBestScore {
					isBetter = true
				}
			}

			if isBetter {
				oldBest := globalBest
				globalBest = genBest
				safePrintf(">>> 🏆 [%s] NEW BEST (Score: %.2f): [%d/%d] C:%d %s\n",
					p.Name,
					calculateWeightedScore(globalBest),
					globalBest.SuccessCount,
					globalBest.TotalCount,
					globalBest.Complexity,
					globalBest.Strategy)

				if oldBest.TotalCount > 0 {
					// Debug info on replacement
					safePrintf("    (Replaced: [%d/%d] C:%d)\n", oldBest.SuccessCount, oldBest.TotalCount, oldBest.Complexity)
				}
			}
		}

		successPct := 0
		if globalBest.TotalCount > 0 {
			successPct = (globalBest.SuccessCount * 100) / globalBest.TotalCount
		}

		if successPct >= p.SuccessRate {
			safePrintf("\n>>> ✅ [%s] Target Success Rate (%d%%) Achieved!\n", p.Name, p.SuccessRate)
			break
		}

		// Selection for next generation
		if len(results) == 0 {
			safePrintf("\033[33m>>> Gen failed. Injecting chaos.\033[0m\n")
			currentGenStrats = genes.GenerateChaosPopulation(model.PopulationSize, discoveredBins)
			continue
		}

		currentGenStrats = genes.BreedingProtocol(results, model.PopulationSize, discoveredBins)
	}

	return globalBest
}

func calculateWeightedScore(res model.StrategyResult) float64 {
	if res.TotalCount == 0 {
		return 0
	}
	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0

	// Penalty Factor:
	// Complexity is ~1-3 for simple, ~10+ for bloated.
	// We want to penalize bloated strategies heavily if success rate is comparable.
	// 0.5% penalty per complexity point.
	penalty := float64(res.Complexity) * 0.5

	return successRate - penalty
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
	var processedMu sync.Mutex

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
	// Track best success count locally for this batch to filter log spam
	var bestSuccessCount int32
	if currentBest.TotalCount > 0 {
		bestSuccessCount = int32(currentBest.SuccessCount)
	}

	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-ticker.C:
				processedMu.Lock()
				current := processedInBatch
				processedMu.Unlock()
				bs := atomic.LoadInt32(&bestSuccessCount)
				safeProgress(">>> ⏳ Processing: %d/%d (Max Success: %d)", current, totalInBatch, bs)
			}
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
				Complexity:   calculateComplexity(g),
			}

			if res.Success {
				// LOGGING LOGIC: Only print if this result is strictly BETTER than what we've seen so far.
				// This prevents spamming the logs with "2/4" if we already know "2/4" exists.
				// Exception: If currentBest is 0, we accept anything > 0.
				currentMax := atomic.LoadInt32(&bestSuccessCount)
				if int32(res.SuccessCount) > currentMax {
					// Attempt to update the max. Only the winner gets to print.
					if atomic.CompareAndSwapInt32(&bestSuccessCount, currentMax, int32(res.SuccessCount)) {
						safePrintf("\033[32;1m🔥 [%.1fs] [%d/%d] C:%d %s\033[0m\n", dur.Seconds(), res.SuccessCount, res.TotalCount, sr.Complexity, g)
					}
				}
			}

			resultsCh <- sr

			processedMu.Lock()
			processedInBatch++
			processedMu.Unlock()
		}(gene)
	}

	wg.Wait()
	close(stopProgress)
	close(resultsCh)
	safePrintf(">>> Batch finished in %.2fs. Processing complete.\n", time.Since(startBatch).Seconds())

	for res := range resultsCh {
		if res.Success {
			results = append(results, res)
		}
	}

	// SORTING: Weighted Score DESC
	sort.Slice(results, func(i, j int) bool {
		s1 := calculateWeightedScore(results[i])
		s2 := calculateWeightedScore(results[j])
		return s1 > s2
	})

	safePrintf(">>> ✅ Found %d working strategies.\n", len(results))
	return results, processedInBatch
}

// calculateComplexity adds a penalty for high repeats and TTLs
func calculateComplexity(s string) int {
	score := 0
	// Base cost for complexity
	if strings.Contains(s, "fake") {
		score += 1
	}
	if strings.Contains(s, "split") {
		score += 2
	}

	// Repeats penalty (Non-Linear)
	// 1-3: OK
	// 4-6: Expensive
	// >6: Very Expensive
	repeats := 1
	if i := strings.Index(s, "repeats="); i != -1 {
		var val int
		fmt.Sscanf(s[i+8:], "%d", &val)
		if val > 0 {
			repeats = val
		}
	}
	if repeats <= 3 {
		score += repeats
	} else if repeats <= 6 {
		score += repeats * 2
	} else {
		score += repeats * 4 // Heavy penalty for repeats > 6
	}

	// TTL penalty
	ttl := 0
	if i := strings.Index(s, "ttl="); i != -1 {
		var val int
		fmt.Sscanf(s[i+4:], "%d", &val)
		if val > 0 {
			ttl = val
		}
	}
	if i := strings.Index(s, "autottl="); i != -1 {
		var val int
		fmt.Sscanf(s[i+8:], "%d", &val)
		if val > 0 {
			ttl = val
		}
	}
	score += ttl

	return score
}
