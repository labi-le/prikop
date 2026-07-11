package orchestrator

import (
	"context"
	"prikop/internal/container"
	"prikop/internal/evolution"
	"prikop/internal/galaxy"
	"prikop/internal/model"
	"prikop/internal/nfqws2"
	"prikop/internal/verifier/types"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	MinGensForIdealExit = 2
	// Complexity is nfqws2.Strategy.Complexity() = number of actions + params.
	MaxComplexityTCP = 6
	MaxComplexityUDP = 10
	SimpleComplexity = 2
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
	p types.ProviderDefinition,
	bins []string,
	report model.ReconReport,
	seed *nfqws2.Strategy,
) *model.ScoredStrategy {
	proto := p.Proto
	if proto == "" {
		proto = "tcp"
	}

	threshold := p.SuccessThreshold
	if threshold == 0 {
		threshold = 1.0
	}

	phaseLog := o.log.With().Str("group", p.Name).Str("proto", proto).Str("filters", p.Filters).Logger()

	// --- PRE-FLIGHT CHECK (Reuse Global Best) ---
	if seed != nil {
		phaseLog.Info().Str("seed", seed.String()).Msg("Testing seed strategy (Global Best)")
		seedResults := o.executeBatch(ctx, []nfqws2.Strategy{*seed}, p.Name, p.Filters, 0) // Test on all targets
		if len(seedResults) > 0 {
			res := seedResults[0]
			successRate := float64(res.Result.SuccessCount) / float64(res.Result.TotalCount)
			if successRate >= threshold {
				phaseLog.Info().Float64("rate", successRate).Msg("Seed strategy works perfectly. Skipping evolution.")
				return &res
			}
			phaseLog.Debug().Float64("rate", successRate).Msg("Seed strategy insufficient, starting evolution.")
		}
	}

	population := galaxy.GenerateZeroGeneration(bins, report, proto)

	// If seed didn't pass but is of same protocol, inject it as a strong parent
	if seed != nil && ((proto == "tcp" && !seed.IsUDP()) || (proto == "udp" && seed.IsUDP())) {
		population = append(population, *seed)
	}

	var globalBest *model.ScoredStrategy

	phaseLog.Info().Float64("threshold", threshold).Msg("Starting phase")

	for gen := 0; gen < p.Gens; gen++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		genLog := phaseLog.With().Int("gen", gen).Int("max_gens", p.Gens).Int("population", len(population)).Logger()
		genLog.Info().Msg("Starting generation")

		maxTargets := 0
		if gen == 0 {
			maxTargets = 1
		}

		results := o.executeBatch(ctx, population, p.Name, p.Filters, maxTargets)

		if ctx.Err() != nil {
			return nil
		}

		sort.Slice(results, func(i, j int) bool {
			s1, _ := results[i].Config.(nfqws2.Strategy)
			s2, _ := results[j].Config.(nfqws2.Strategy)
			return evolution.CalculateScore(results[i].Result, results[i].Complexity, s1) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity, s2)
		})

		if len(results) > 0 {
			bestGen := results[0]
			sBest, _ := bestGen.Config.(nfqws2.Strategy)
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity, sBest)

			if bestGen.Result.SuccessCount > 0 {
				if globalBest == nil {
					globalBest = &bestGen
					o.logNewBest(genLog, globalBest)
				} else {
					sGlobal, _ := globalBest.Config.(nfqws2.Strategy)
					globalScore := evolution.CalculateScore(globalBest.Result, globalBest.Complexity, sGlobal)

					if score > globalScore {
						globalBest = &bestGen
						o.logNewBest(genLog, globalBest)
					}
				}
			}
		}

		if globalBest != nil && globalBest.Result.SuccessCount > 0 && gen > MinGensForIdealExit {
			successRate := float64(globalBest.Result.SuccessCount) / float64(globalBest.Result.TotalCount)

			if successRate >= threshold {
				sBest, _ := globalBest.Config.(nfqws2.Strategy)
				isMasking := sBest.HasFunc("fake")
				maxComp := MaxComplexityTCP
				if proto == "udp" {
					maxComp = MaxComplexityUDP
				}

				if (isMasking && globalBest.Complexity <= maxComp) || globalBest.Complexity == SimpleComplexity {
					genLog.Info().Float64("rate", successRate).Msg("Ideal strategy found (Masking/Simple), skipping remaining generations.")
					break
				}
			}
		}

		population = evolution.Evolve(results, globalBest, bins, proto, report, genLog)

		if len(population) == 0 {
			genLog.Warn().Msg("Population extinct. Regenerating fresh generation to continue search.")
			population = galaxy.GenerateZeroGeneration(bins, report, proto)
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

func (o *Optimizer) executeBatch(ctx context.Context, strats []nfqws2.Strategy, group string, filters string, maxTargets int) []model.ScoredStrategy {
	var wg sync.WaitGroup
	results := make([]model.ScoredStrategy, len(strats))
	filterArgs := strings.Fields(filters)

	type resultEntry struct {
		idx int
		s   model.ScoredStrategy
	}
	resChan := make(chan resultEntry, len(strats))

	for i, s := range strats {
		wg.Add(1)
		go func(idx int, strat nfqws2.Strategy) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			start := time.Now()
			req := model.WorkerRequest{
				StrategyArgs: strat.ToArgs(),
				TargetGroup:  group,
				Filters:      filterArgs,
				MaxTargets:   maxTargets,
			}

			// We don't use a local limit here, we rely on the Pool's internal worker channel
			res, err := o.Pool.Exec(ctx, req)

			duration := time.Since(start)
			scored := model.ScoredStrategy{
				Config:     strat,
				RawArgs:    strat.String(),
				Duration:   duration,
				Result:     res,
				Complexity: strat.Complexity(),
			}

			if err != nil {
				scored.Result.Error = err.Error()
			}

			resChan <- resultEntry{idx: idx, s: scored}
		}(i, s)
	}

	// Helper to close channel when all goroutines finished
	go func() {
		wg.Wait()
		close(resChan)
	}()

	// Collect results from channel
	collected := 0
	for collected < len(strats) {
		select {
		case r, ok := <-resChan:
			if !ok {
				return results
			}
			results[r.idx] = r.s
			collected++
		case <-ctx.Done():
			return results
		}
	}

	return results
}
