package evolution

import (
	"math/rand/v2"
	"sort"

	"prikop/internal/model"
	"prikop/internal/nfqws2"

	"github.com/rs/zerolog"
)

const (
	PopulationSize    = 100
	ScoreMaskingBonus = 15.0
	// Penalties for "dirty" methods that break behind NAT.
	PenaltyBadSum = 20.0
	PenaltyBadSeq = 10.0

	IdealScoreBonus   = 50.0
	RobustSuccessRate = 30.0
	ComplexityWeight  = 0.5

	SurvivorSuccessThreshold = 0
	ClusterMinSizeForBackup  = 3
)

func Evolve(results []model.ScoredStrategy, globalBest *model.ScoredStrategy, discoveredBins []string, proto string, report model.ReconReport, log zerolog.Logger) []nfqws2.Strategy {
	var nextGen []nfqws2.Strategy
	mutator := NewMutator(discoveredBins, proto)

	var survivors []model.ScoredStrategy
	for _, r := range results {
		if r.Result.SuccessCount > SurvivorSuccessThreshold {
			survivors = append(survivors, r)
		}
	}

	// Add global best to survivors if it's not already there.
	if globalBest != nil {
		found := false
		for _, s := range survivors {
			if s.Config.String() == globalBest.Config.String() {
				found = true
				break
			}
		}
		if !found {
			survivors = append(survivors, *globalBest)
		}
	}

	if len(survivors) == 0 {
		log.Warn().Msg("EXTINCTION: No strategies survived. Regenerating random population.")
		return nil
	}

	clusters := make(map[string][]model.ScoredStrategy)
	for _, r := range survivors {
		strat, ok := r.Config.(nfqws2.Strategy)
		if !ok {
			continue
		}
		key := strat.Signature()
		if strat.HasFunc("split") || strat.HasFunc("disorder") {
			key += "|" + strat.SplitPos()
		}
		clusters[key] = append(clusters[key], r)
	}

	log.Info().Int("diversity", len(clusters)).Msg("Unique working architectures survived.")

	var bestParents []model.ScoredStrategy

	for _, cluster := range clusters {
		sort.Slice(cluster, func(i, j int) bool {
			s1, _ := cluster[i].Config.(nfqws2.Strategy)
			s2, _ := cluster[j].Config.(nfqws2.Strategy)
			return CalculateScore(cluster[i].Result, cluster[i].Complexity, s1) >
				CalculateScore(cluster[j].Result, cluster[j].Complexity, s2)
		})

		bestParents = append(bestParents, cluster[0])
		if s, ok := cluster[0].Config.(nfqws2.Strategy); ok {
			nextGen = append(nextGen, s.Clone())
		}

		if len(cluster) > ClusterMinSizeForBackup && cluster[0].Result.SuccessCount == cluster[0].Result.TotalCount {
			if s, ok := cluster[1].Config.(nfqws2.Strategy); ok {
				nextGen = append(nextGen, s.Clone())
			}
		}
	}

	slotsRemaining := PopulationSize - len(nextGen)
	if slotsRemaining < 0 {
		slotsRemaining = 0
	}

	if len(bestParents) > 0 {
		for range slotsRemaining {
			parent := bestParents[rand.IntN(len(bestParents))]
			if s, ok := parent.Config.(nfqws2.Strategy); ok {
				child := s.Clone() // deep copy: never share Param slices with the parent
				mutations := 1
				if parent.Result.TotalCount > 0 {
					rate := float64(parent.Result.SuccessCount) / float64(parent.Result.TotalCount)
					if rate < 0.5 {
						mutations += 10 // +10 mutations to the god of mutations
					}
				}
				for range mutations {
					mutator.SmartMutate(&child, parent.Result.FailureType)
				}
				nextGen = append(nextGen, child)
			}
		}
	}

	if len(nextGen) > PopulationSize {
		nextGen = nextGen[:PopulationSize]
	}

	return nextGen
}

func CalculateScore(res model.WorkerResult, complexity int, strat nfqws2.Strategy) float64 {
	if res.TotalCount == 0 || res.SuccessCount == 0 {
		return 0
	}

	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0
	score := successRate

	// Bonus for flawless operation.
	if res.SuccessCount == res.TotalCount {
		score += IdealScoreBonus
	}

	// Penalties for unreliable methods.
	if strat.HasParam("badsum") {
		score -= PenaltyBadSum
	}
	if strat.HasBadSeq() {
		score -= PenaltyBadSeq
	}

	// Bonus for masking (fake/disorder) when the strategy actually works.
	if successRate > RobustSuccessRate {
		if strat.HasFunc("fake") || strat.HasFunc("disorder") {
			score += ScoreMaskingBonus
		}
	}

	// Small complexity penalty, preferring simpler solutions.
	score -= float64(complexity) * ComplexityWeight

	if score < 0 {
		score = 0
	}

	return score
}
