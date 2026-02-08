package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"prikop/internal/container"
	"prikop/internal/evolution"
	"prikop/internal/galaxy"
	"prikop/internal/model"
	"prikop/internal/nfqws"
)

const (
	StagnationThreshold = 3
	MinGensForIdealExit = 2
	MaxComplexityTCP    = 3
	MaxComplexityUDP    = 6
	SimpleComplexity    = 1
	WorkerLimit         = 50
)

// Optimizer handles the evolutionary process for a specific phase
type Optimizer struct {
	Pool *container.WorkerPool
}

func NewOptimizer(pool *container.WorkerPool) *Optimizer {
	return &Optimizer{Pool: pool}
}

func (o *Optimizer) RunPhase(
	ctx context.Context,
	group string,
	bins []string,
	maxGens int,
	report model.ReconReport,
	filters string,
) *model.ScoredStrategy {
	// 1. Determine Protocol context
	proto := "tcp"
	if strings.Contains(group, "udp") || strings.Contains(group, "l7") {
		proto = "udp"
	}

	population := galaxy.GenerateZeroGeneration(bins, report, proto)
	var globalBest *model.ScoredStrategy

	fmt.Printf(">>> Starting Phase: %s [Proto: %s] [Filters: %s]\n", group, proto, filters)

	// Stagnation tracking
	stagnationCount := 0
	lastBestSuccess := 0
	reinforcementVariant := 0

	for gen := 0; gen < maxGens; gen++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		fmt.Printf(">>> GEN %d/%d (%d strategies) [Proto: %s]\n", gen, maxGens, len(population), proto)

		results := o.executeBatch(ctx, population, group, filters)

		if ctx.Err() != nil {
			return nil
		}

		sort.Slice(results, func(i, j int) bool {
			s1, _ := results[i].Config.(nfqws.Strategy)
			s2, _ := results[j].Config.(nfqws.Strategy)
			return evolution.CalculateScore(results[i].Result, results[i].Complexity, s1) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity, s2)
		})

		// --- PANIC MODE CHECK ---
		// If Gen 0 failed completely (no survivors with >0 success),
		// we discard everything and try Primitives (Atomic Scan).
		if gen == 0 {
			anySuccess := false
			for _, r := range results {
				if r.Result.SuccessCount > 0 {
					anySuccess = true
					break
				}
			}

			if !anySuccess {
				fmt.Println("    [!] ALL SNIPERS MISSED. Engaging Panic Mode: Primitives Scan.")
				population = galaxy.GeneratePrimitives(bins, proto)
				// Reset loop state effectively restarting as Gen 1
				continue
			}
		}
		// ------------------------

		if len(results) > 0 {
			bestGen := results[0]
			sBest, _ := bestGen.Config.(nfqws.Strategy)
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity, sBest)

			// Only consider strategies with at least one success
			if bestGen.Result.SuccessCount > 0 {
				if globalBest == nil {
					globalBest = &bestGen
					o.logNewBest(globalBest)
					lastBestSuccess = bestGen.Result.SuccessCount
				} else {
					sGlobal, _ := globalBest.Config.(nfqws.Strategy)
					globalScore := evolution.CalculateScore(globalBest.Result, globalBest.Complexity, sGlobal)

					if score > globalScore {
						globalBest = &bestGen
						o.logNewBest(globalBest)
					}
				}

				if globalBest.Result.SuccessCount > lastBestSuccess {
					stagnationCount = 0
					lastBestSuccess = globalBest.Result.SuccessCount
				} else {
					stagnationCount++
				}
			}
		}

		// Early exit: Ideal strategy found
		if globalBest != nil && globalBest.Result.SuccessCount > 0 && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > MinGensForIdealExit {
			sBest, _ := globalBest.Config.(nfqws.Strategy)
			isMasking := strings.Contains(sBest.Mode, "fake") || strings.Contains(sBest.Mode, "hostfake")
			maxComp := MaxComplexityTCP
			if proto == "udp" {
				maxComp = MaxComplexityUDP
			}

			if (isMasking && globalBest.Complexity <= maxComp) || globalBest.Complexity == SimpleComplexity {
				fmt.Println(">>> Ideal strategy found (Masking/Simple), skipping remaining generations.")
				break
			}
		}

		// Evolve existing population
		population = evolution.Evolve(results, bins, proto)

		// INJECT REINFORCEMENTS logic
		if stagnationCount >= StagnationThreshold && globalBest != nil && globalBest.Result.SuccessCount < globalBest.Result.TotalCount {
			fmt.Printf("    [!] Stagnation detected (%d gens). Injecting reinforcements (Variant %d)...\n", stagnationCount, reinforcementVariant)

			reinforcements := galaxy.GenerateReinforcements(bins, proto, reinforcementVariant)
			reinforcementVariant++

			injectIdx := len(population) - len(reinforcements)
			if injectIdx < 0 {
				injectIdx = 0
			}

			for i, r := range reinforcements {
				if injectIdx+i < len(population) {
					population[injectIdx+i] = r
				} else {
					population = append(population, r)
				}
			}
			stagnationCount = 0
		}

		if len(population) == 0 {
			break
		}
	}

	return globalBest
}

func (o *Optimizer) logNewBest(best *model.ScoredStrategy) {
	fmt.Printf(">>> NEW BEST: %s (Success: %d/%d)\n", best.Config.String(), best.Result.SuccessCount, best.Result.TotalCount)
	o.logResultDetails(best)
}

func (o *Optimizer) executeBatch(ctx context.Context, strats []nfqws.Strategy, group string, filters string) []model.ScoredStrategy {
	var wg sync.WaitGroup
	results := make([]model.ScoredStrategy, len(strats))

	filterArgs := strings.Fields(filters)
	limit := make(chan struct{}, WorkerLimit)

	for i, s := range strats {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(idx int, strat nfqws.Strategy) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()

			if ctx.Err() != nil {
				return
			}

			start := time.Now()
			req := model.WorkerRequest{
				StrategyArgs: strat.ToArgs(),
				TargetGroup:  group,
				Filters:      filterArgs,
			}

			res, err := o.Pool.Exec(ctx, req)

			duration := time.Since(start)
			scored := model.ScoredStrategy{
				Config:     strat,
				RawArgs:    strat.String(),
				Duration:   duration,
				Result:     res,
				Complexity: strat.Repeats,
			}

			if err != nil {
				scored.Result.Error = err.Error()
			}

			results[idx] = scored
		}(i, s)
	}
	wg.Wait()
	return results
}

func (o *Optimizer) logResultDetails(best *model.ScoredStrategy) {
	if len(best.Result.Passed) > 0 {
		fmt.Println("    [+] PASSED:")
		for _, u := range best.Result.Passed {
			fmt.Printf("        %s\n", u)
		}
	}
	if len(best.Result.Failed) > 0 {
		fmt.Println("    [-] FAILED:")
		for _, u := range best.Result.Failed {
			fmt.Printf("        %s\n", u)
		}
	}
}
