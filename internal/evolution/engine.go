package evolution

import (
	"math/rand"
	"sort"
	"strings"

	"prikop/internal/model"
	"prikop/internal/nfqws"

	"github.com/rs/zerolog"
)

const (
	PopulationSize    = 100
	ScoreMaskingBonus = 15.0
	// Штрафы за "грязные" методы, которые ломаются за NAT
	PenaltyBadSum = 20.0
	PenaltyBadSeq = 10.0

	IdealScoreBonus   = 50.0
	RobustSuccessRate = 30.0
	ComplexityWeight  = 0.5

	SurvivorSuccessThreshold = 0
	ClusterMinSizeForBackup  = 3
)

func Evolve(results []model.ScoredStrategy, discoveredBins []string, proto string, log zerolog.Logger) []nfqws.Strategy {
	var nextGen []nfqws.Strategy
	mutator := NewMutator(discoveredBins, proto)

	var survivors []model.ScoredStrategy
	for _, r := range results {
		if r.Result.SuccessCount > SurvivorSuccessThreshold {
			survivors = append(survivors, r)
		}
	}

	if len(survivors) == 0 {
		log.Warn().Msg("EXTINCTION: No strategies survived.")
		return nil
	}

	clusters := make(map[string][]model.ScoredStrategy)
	for _, r := range survivors {
		strat, ok := r.Config.(nfqws.Strategy)
		if !ok {
			continue
		}
		key := strat.Mode
		if strings.Contains(strat.Mode, "split") || strings.Contains(strat.Mode, "disorder") {
			key += "|" + strat.Split.Pos
		}
		clusters[key] = append(clusters[key], r)
	}

	log.Info().Int("diversity", len(clusters)).Msg("Unique working architectures survived.")

	var bestParents []model.ScoredStrategy

	for _, cluster := range clusters {
		sort.Slice(cluster, func(i, j int) bool {
			s1, _ := cluster[i].Config.(nfqws.Strategy)
			s2, _ := cluster[j].Config.(nfqws.Strategy)
			return CalculateScore(cluster[i].Result, cluster[i].Complexity, s1) >
				CalculateScore(cluster[j].Result, cluster[j].Complexity, s2)
		})

		bestParents = append(bestParents, cluster[0])
		if s, ok := cluster[0].Config.(nfqws.Strategy); ok {
			nextGen = append(nextGen, s)
		}

		if len(cluster) > ClusterMinSizeForBackup && cluster[0].Result.SuccessCount == cluster[0].Result.TotalCount {
			if s, ok := cluster[1].Config.(nfqws.Strategy); ok {
				nextGen = append(nextGen, s)
			}
		}
	}

	slotsRemaining := PopulationSize - len(nextGen)
	if slotsRemaining < 0 {
		slotsRemaining = 0
	}

	if len(bestParents) > 0 {
		for i := 0; i < slotsRemaining; i++ {
			parent := bestParents[rand.Intn(len(bestParents))]
			if s, ok := parent.Config.(nfqws.Strategy); ok {
				child := s
				mutations := 1
				if parent.Result.TotalCount > 0 {
					rate := float64(parent.Result.SuccessCount) / float64(parent.Result.TotalCount)
					if rate < 0.5 {
						mutations += 10 // + 10 мутаций богу мутаций
					}
				}
				for m := 0; m < mutations; m++ {
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

func CalculateScore(res model.WorkerResult, complexity int, strat nfqws.Strategy) float64 {
	if res.TotalCount == 0 || res.SuccessCount == 0 {
		return 0
	}

	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0
	score := successRate

	// Бонус за идеальную работу
	if res.SuccessCount == res.TotalCount {
		score += IdealScoreBonus
	}

	// Штрафы за ненадежные методы
	if strat.Fooling.BadSum {
		score -= PenaltyBadSum
	}
	if strat.Fooling.BadSeq {
		score -= PenaltyBadSeq
	}

	// Бонус за маскировку (Fake), если стратегия работает
	if successRate > RobustSuccessRate {
		isRobust := strings.Contains(strat.Mode, "fake") || strings.Contains(strat.Mode, "disorder")
		if isRobust {
			score += ScoreMaskingBonus
		}
	}

	// Небольшой штраф за сложность (длину команды), чтобы предпочитать простые решения
	penalty := float64(complexity) * ComplexityWeight
	score -= penalty

	if score < 0 {
		score = 0
	}

	return score
}
