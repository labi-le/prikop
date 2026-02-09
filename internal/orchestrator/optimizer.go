package orchestrator

import (
	"context"
	"prikop/internal/container"
	"prikop/internal/evolution"
	"prikop/internal/galaxy"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
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
	log  zerolog.Logger
}

func NewOptimizer(pool *container.WorkerPool, log zerolog.Logger) *Optimizer {
	return &Optimizer{Pool: pool, log: log}
}

func (o *Optimizer) RunPhase(
	ctx context.Context,
	group string,
	bins []string,
	maxGens int,
	report model.ReconReport,
	filters string,
) *model.ScoredStrategy {
	proto := "tcp"
	if strings.Contains(group, "udp") || strings.Contains(group, "l7") {
		proto = "udp"
	}
	phaseLog := o.log.With().Str("group", group).Str("proto", proto).Str("filters", filters).Logger()

	population := galaxy.GenerateZeroGeneration(bins, report, proto)
	var globalBest *model.ScoredStrategy

	phaseLog.Info().Msg("Starting phase")

	stagnationCount := 0
	lastBestSuccess := 0
	reinforcementVariant := 0

	for gen := 0; gen < maxGens; gen++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		genLog := phaseLog.With().Int("gen", gen).Int("max_gens", maxGens).Int("population", len(population)).Logger()
		genLog.Info().Msg("Starting generation")

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

		if gen == 0 {
			anySuccess := false
			for _, r := range results {
				if r.Result.SuccessCount > 0 {
					anySuccess = true
					break
				}
			}

			if !anySuccess {
				genLog.Warn().Msg("All snipers missed. Engaging Panic Mode: Primitives Scan.")
				population = galaxy.GeneratePrimitives(bins, proto)
				continue
			}
		}

		if len(results) > 0 {
			bestGen := results[0]
			sBest, _ := bestGen.Config.(nfqws.Strategy)
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity, sBest)

			if bestGen.Result.SuccessCount > 0 {
				if globalBest == nil {
					globalBest = &bestGen
					o.logNewBest(genLog, globalBest)
					lastBestSuccess = bestGen.Result.SuccessCount
				} else {
					sGlobal, _ := globalBest.Config.(nfqws.Strategy)
					globalScore := evolution.CalculateScore(globalBest.Result, globalBest.Complexity, sGlobal)

					if score > globalScore {
						globalBest = &bestGen
						o.logNewBest(genLog, globalBest)
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

		if globalBest != nil && globalBest.Result.SuccessCount > 0 && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > MinGensForIdealExit {
			sBest, _ := globalBest.Config.(nfqws.Strategy)
			isMasking := strings.Contains(sBest.Mode, "fake") || strings.Contains(sBest.Mode, "hostfake")
			maxComp := MaxComplexityTCP
			if proto == "udp" {
				maxComp = MaxComplexityUDP
			}

			if (isMasking && globalBest.Complexity <= maxComp) || globalBest.Complexity == SimpleComplexity {
				genLog.Info().Msg("Ideal strategy found (Masking/Simple), skipping remaining generations.")
				break
			}
		}

		population = evolution.Evolve(results, bins, proto, genLog)

		if stagnationCount >= StagnationThreshold && globalBest != nil && globalBest.Result.SuccessCount < globalBest.Result.TotalCount {
			genLog.Warn().Int("stagnation_count", stagnationCount).Int("variant", reinforcementVariant).Msg("Stagnation detected. Injecting reinforcements.")

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
			genLog.Warn().Msg("Population extinct. Ending phase.")
			break
		}
	}

	return globalBest
}

func (o *Optimizer) logNewBest(log zerolog.Logger, best *model.ScoredStrategy) {
	log.Info().
		Str("strategy", best.Config.String()).
		Int("success", best.Result.SuccessCount).
		Int("total", best.Result.TotalCount).
		Msg("New best strategy found")

	if len(best.Result.Passed) > 0 {
		log.Debug().Strs("passed", best.Result.Passed).Msg("Passed targets")
	}
	if len(best.Result.Failed) > 0 {
		log.Debug().Strs("failed", best.Result.Failed).Msg("Failed targets")
	}
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
