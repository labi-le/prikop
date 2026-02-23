package orchestrator

import (
	"context"
	"prikop/internal/container"
	"prikop/internal/evolution"
	"prikop/internal/galaxy"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"prikop/internal/verifier/types"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	MinGensForIdealExit = 2
	MaxComplexityTCP    = 3
	MaxComplexityUDP    = 6
	SimpleComplexity    = 1
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

	population := galaxy.GenerateZeroGeneration(bins, report, proto)
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
			s1, _ := results[i].Config.(nfqws.Strategy)
			s2, _ := results[j].Config.(nfqws.Strategy)
			return evolution.CalculateScore(results[i].Result, results[i].Complexity, s1) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity, s2)
		})

		if len(results) > 0 {
			bestGen := results[0]
			sBest, _ := bestGen.Config.(nfqws.Strategy)
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity, sBest)

			if bestGen.Result.SuccessCount > 0 {
				if globalBest == nil {
					globalBest = &bestGen
					o.logNewBest(genLog, globalBest)
				} else {
					sGlobal, _ := globalBest.Config.(nfqws.Strategy)
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
				sBest, _ := globalBest.Config.(nfqws.Strategy)
				isMasking := strings.Contains(sBest.Mode, "fake") || strings.Contains(sBest.Mode, "hostfake")
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

func (o *Optimizer) executeBatch(ctx context.Context, strats []nfqws.Strategy, group string, filters string, maxTargets int) []model.ScoredStrategy {
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
		go func(idx int, strat nfqws.Strategy) {
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
				Complexity: strat.Repeats,
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
