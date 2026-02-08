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

// Optimizer handles the evolutionary process for a specific phase
type Optimizer struct {
	Pool *container.WorkerPool
}

func NewOptimizer(pool *container.WorkerPool) *Optimizer {
	return &Optimizer{Pool: pool}
}

func (o *Optimizer) RunPhase(ctx context.Context, group string, bins []string, maxGens int, report model.ReconReport) *model.ScoredStrategy {
	// 1. Determine Protocol context
	proto := "tcp"
	if strings.Contains(group, "udp") || strings.Contains(group, "l7") {
		proto = "udp"
	}

	population := galaxy.GenerateZeroGeneration(bins, report, proto)
	var globalBest *model.ScoredStrategy

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

		results := o.executeBatch(ctx, population, group)

		if ctx.Err() != nil {
			return nil
		}

		sort.Slice(results, func(i, j int) bool {
			s1, _ := results[i].Config.(nfqws.Strategy)
			s2, _ := results[j].Config.(nfqws.Strategy)
			return evolution.CalculateScore(results[i].Result, results[i].Complexity, s1) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity, s2)
		})

		if len(results) > 0 {
			bestGen := results[0]
			sBest, _ := bestGen.Config.(nfqws.Strategy)
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity, sBest)

			if globalBest == nil {
				globalBest = &bestGen
				o.logNewBest(globalBest)
				lastBestSuccess = bestGen.Result.SuccessCount
			} else {
				sGlobal, _ := globalBest.Config.(nfqws.Strategy)
				globalScore := evolution.CalculateScore(globalBest.Result, globalBest.Complexity, sGlobal)

				// Update global best if better score OR (same score but less complex)
				if score > globalScore {
					globalBest = &bestGen
					o.logNewBest(globalBest)
				}
			}

			// Stagnation Check
			// We check against the *current generation's* max success compared to global.
			// If current gen didn't beat previous records, we are stagnant.
			if globalBest.Result.SuccessCount > lastBestSuccess {
				stagnationCount = 0
				lastBestSuccess = globalBest.Result.SuccessCount
			} else {
				stagnationCount++
			}
		}

		// Early exit: Ideal strategy AND mask preference satisfied (if used)
		if globalBest != nil && globalBest.Result.SuccessCount > 0 && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > 2 {
			sBest, _ := globalBest.Config.(nfqws.Strategy)
			isMasking := strings.Contains(sBest.Mode, "fake") || strings.Contains(sBest.Mode, "hostfake")
			maxComp := 3
			if proto == "udp" {
				maxComp = 6
			}

			if (isMasking && globalBest.Complexity <= maxComp) || globalBest.Complexity == 1 {
				fmt.Println(">>> Ideal strategy found (Masking/Simple), skipping remaining generations.")
				break
			}
		}

		// Evolve existing population
		population = evolution.Evolve(results, bins, proto)

		// INJECT REINFORCEMENTS logic
		// If stagnant for 3 gens and not perfect
		if stagnationCount >= 3 && globalBest != nil && globalBest.Result.SuccessCount < globalBest.Result.TotalCount {
			fmt.Printf("    [!] Stagnation detected (%d gens). Injecting reinforcements (Variant %d)...\n", stagnationCount, reinforcementVariant)

			reinforcements := galaxy.GenerateReinforcements(bins, proto, reinforcementVariant)
			reinforcementVariant++

			// Replace the tail of the population with new snipers
			// We keep the top elite from Evolve(), but replace the "random new" ones
			injectIdx := len(population) - len(reinforcements)
			if injectIdx < 0 {
				injectIdx = 0
			} // Safety

			// We overwrite the worst strategies (which are at the end) with our crafted ones
			for i, r := range reinforcements {
				if injectIdx+i < len(population) {
					population[injectIdx+i] = r
				} else {
					population = append(population, r)
				}
			}

			// Reset stagnation slightly to give reinforcements a chance to breed
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

func (o *Optimizer) executeBatch(ctx context.Context, strats []nfqws.Strategy, group string) []model.ScoredStrategy {
	var wg sync.WaitGroup
	results := make([]model.ScoredStrategy, len(strats))

	// Semaphore to prevent Docker exhaustion if pool is large but limited
	limit := make(chan struct{}, 50)

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
