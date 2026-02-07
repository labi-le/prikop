package orchestrator

import (
	"context"
	"fmt"
	"sort"
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
	population := galaxy.GenerateZeroGeneration(bins, report)
	var globalBest *model.ScoredStrategy

	for gen := 0; gen < maxGens; gen++ {
		// CHECKPOINT: Check before generation
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		fmt.Printf(">>> GEN %d/%d (%d strategies)\n", gen, maxGens, len(population))

		results := o.executeBatch(ctx, population, group)

		// If context died during executeBatch
		if ctx.Err() != nil {
			return nil
		}

		sort.Slice(results, func(i, j int) bool {
			return evolution.CalculateScore(results[i].Result, results[i].Complexity) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity)
		})

		if len(results) > 0 {
			bestGen := results[0]
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity)

			if globalBest == nil || score > evolution.CalculateScore(globalBest.Result, globalBest.Complexity) {
				globalBest = &bestGen
				fmt.Printf(">>> NEW BEST: %s (Success: %d/%d)\n", globalBest.Config.ToArgs(), globalBest.Result.SuccessCount, globalBest.Result.TotalCount)
				o.logResultDetails(globalBest)
			}
		}

		// Early exit condition (Ideal strategy)
		if globalBest != nil && globalBest.Result.SuccessCount > 0 && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > 3 {
			if globalBest.Complexity <= 2 {
				fmt.Println(">>> Ideal strategy found, skipping remaining generations.")
				break
			}
		}

		population = evolution.Evolve(results, bins)
		if len(population) == 0 {
			break
		}
	}

	return globalBest
}

func (o *Optimizer) executeBatch(ctx context.Context, strats []nfqws.Strategy, group string) []model.ScoredStrategy {
	var wg sync.WaitGroup
	results := make([]model.ScoredStrategy, len(strats))

	for i, s := range strats {
		// CHECKPOINT: Don't spawn new goroutines if context is dead
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(idx int, strat nfqws.Strategy) {
			defer wg.Done()

			// Check inside goroutine before heavy work
			if ctx.Err() != nil {
				return
			}

			start := time.Now()
			req := model.WorkerRequest{
				StrategyArgs: strat.ToArgs(),
				TargetGroup:  group,
			}

			// Pass ctx to Exec
			res, err := o.Pool.Exec(ctx, req)

			duration := time.Since(start)
			scored := model.ScoredStrategy{
				Config:     strat,
				RawArgs:    strat.ToArgs(),
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
