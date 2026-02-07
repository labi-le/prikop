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
			} else {
				sGlobal, _ := globalBest.Config.(nfqws.Strategy)
				globalScore := evolution.CalculateScore(globalBest.Result, globalBest.Complexity, sGlobal)
				if score > globalScore {
					globalBest = &bestGen
					o.logNewBest(globalBest)
				}
			}
		}

		// Early exit: Ideal strategy AND mask preference satisfied (if used)
		if globalBest != nil && globalBest.Result.SuccessCount > 0 && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > 2 {
			sBest, _ := globalBest.Config.(nfqws.Strategy)
			isMasking := strings.Contains(sBest.Mode, "fake") || strings.Contains(sBest.Mode, "hostfake")

			// UDP often needs repeats, so we allow slightly higher complexity for UDP ideal exit
			maxComp := 3
			if proto == "udp" {
				maxComp = 6
			}

			if (isMasking && globalBest.Complexity <= maxComp) || globalBest.Complexity == 1 {
				fmt.Println(">>> Ideal strategy found (Masking/Simple), skipping remaining generations.")
				break
			}
		}

		// Pass proto to Evolve
		population = evolution.Evolve(results, bins, proto)
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
