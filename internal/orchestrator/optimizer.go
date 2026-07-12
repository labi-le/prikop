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
	// Gen0 samples up to this many targets (breadth) instead of a single one, so
	// one flaky/intermittent target can't prune an otherwise-good strategy.
	Gen0Targets = 3
	// ConfirmRepeats re-runs the final winner this many times on all targets; it
	// is kept only if it clears the threshold in a strict majority (fluke filter).
	ConfirmRepeats = 3
)

// Optimizer handles the evolutionary process for a specific phase
type Optimizer struct {
	Pool     *container.WorkerPool
	log      zerolog.Logger
	reporter *Reporter // optional; nil unless -report is set
}

func NewOptimizer(pool *container.WorkerPool, log zerolog.Logger, reporter *Reporter) *Optimizer {
	return &Optimizer{Pool: pool, log: log, reporter: reporter}
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

	// --- BASELINE (no desync): does the target already work unassisted? If so,
	// emit NO strategy — forcing a desync onto an already-open connection can make
	// the DPI flag+throttle it (proven on chaotic/garuda: a working 676 KB download
	// collapsed to a 7.6 KB stall the instant a split profile was added).
	if base, ok := o.runBaseline(ctx, p); ok {
		rate := 0.0
		if base.TotalCount > 0 {
			rate = float64(base.SuccessCount) / float64(base.TotalCount)
		}
		if base.TotalCount > 0 && rate >= threshold {
			phaseLog.Info().Float64("rate", rate).Msg("Target reachable WITHOUT bypass — no strategy needed (a desync here risks making it worse)")
			return &model.ScoredStrategy{Baseline: true, Result: base}
		}
		phaseLog.Info().Float64("rate", rate).Str("reason", string(base.FailureType)).Msg("Baseline blocked — searching for a bypass")
	}

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
		if gen == 0 && len(p.Targets) > Gen0Targets {
			maxTargets = Gen0Targets
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

			o.reporter.recordGen(p.Name, proto, p.Filters, genRecord{
				Gen: gen, Population: len(population),
				Best: bestGen.Config.String(), Score: score,
				Success: bestGen.Result.SuccessCount, Total: bestGen.Result.TotalCount,
			})

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

	// --- CONFIRM the winner is robust, not a lucky single pass. Against
	// probabilistic DPI one pass proves little (discord/chaotic flipped run to
	// run), so re-test on all targets and keep it only on a majority.
	if globalBest != nil && globalBest.Result.SuccessCount > 0 {
		if !o.confirmWinner(ctx, *globalBest, p, threshold) {
			phaseLog.Warn().Msg("Winner failed confirmation (likely a fluke) — discarding")
			return nil
		}
		phaseLog.Info().Msg("Winner confirmed across repeat runs")
	}

	return globalBest
}

// runBaseline measures the provider's targets with NO desync (the worker skips
// iptables/nfqws). It returns the raw result and whether the probe ran, so
// RunPhase can skip evolution entirely when the target is already reachable.
func (o *Optimizer) runBaseline(ctx context.Context, p types.ProviderDefinition) (model.WorkerResult, bool) {
	req := model.WorkerRequest{
		Baseline:    true,
		TargetGroup: p.Name,
		Filters:     strings.Fields(p.Filters),
		MaxTargets:  0, // all targets
	}
	res, err := o.Pool.Exec(ctx, req)
	if err != nil {
		o.log.Warn().Err(err).Str("group", p.Name).Msg("Baseline probe failed; proceeding with evolution")
		return model.WorkerResult{}, false
	}
	return res, true
}

// confirmWinner re-tests a candidate on all targets ConfirmRepeats times and
// reports whether it clears the phase threshold in a strict majority of runs,
// filtering flukes that pass once by chance against probabilistic DPI.
func (o *Optimizer) confirmWinner(ctx context.Context, cand model.ScoredStrategy, p types.ProviderDefinition, threshold float64) bool {
	strat, ok := cand.Config.(nfqws2.Strategy)
	if !ok {
		return true // non-strategy candidate isn't re-testable; don't block it
	}
	passes := 0
	for range ConfirmRepeats {
		if ctx.Err() != nil {
			return passes > 0 // best-effort on cancellation
		}
		res := o.executeBatch(ctx, []nfqws2.Strategy{strat}, p.Name, p.Filters, 0)
		if len(res) == 0 || res[0].Result.TotalCount == 0 {
			continue
		}
		if float64(res[0].Result.SuccessCount)/float64(res[0].Result.TotalCount) >= threshold {
			passes++
		}
	}
	return passes*2 > ConfirmRepeats // strict majority
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
