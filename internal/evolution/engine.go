package evolution

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"prikop/internal/model"
	"prikop/internal/nfqws"
)

const (
	PopulationSize    = 100
	ScoreMaskingBonus = 10.0 // Increased from 5.0 to favor robust masking
	ScoreBadSumBonus  = 2.0
)

func Evolve(results []model.ScoredStrategy, discoveredBins []string, proto string) []nfqws.Strategy {
	var nextGen []nfqws.Strategy
	mutator := NewMutator(discoveredBins, proto)

	clusters := make(map[string][]model.ScoredStrategy)

	for _, r := range results {
		strat, ok := r.Config.(nfqws.Strategy)
		if !ok {
			continue
		}
		// Clusters key
		key := strat.Mode
		// Differentiate fake types in clusters
		if strings.Contains(strat.Mode, "fake") {
			if strat.Fake.Quic != "" {
				key += "-quic"
			} else if strat.Fake.TLS != "" {
				key += "-tls"
			} else if strat.Fake.UnknownUdp != "" {
				key += "-udp"
			}
		} else {
			key += "-" + strat.Split.Pos
		}
		clusters[key] = append(clusters[key], r)
	}

	fmt.Printf("    [i] Diversity: %d unique architectures survived.\n", len(clusters))

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

		if len(cluster) > 3 && cluster[0].Result.SuccessCount > 0 {
			if s, ok := cluster[1].Config.(nfqws.Strategy); ok {
				nextGen = append(nextGen, s)
			}
		}
	}

	slotsRemaining := PopulationSize - len(nextGen)

	if len(bestParents) > 0 {
		for i := 0; i < slotsRemaining; i++ {
			parent := bestParents[rand.Intn(len(bestParents))]
			if s, ok := parent.Config.(nfqws.Strategy); ok {
				child := s
				mutator.SmartMutate(&child, parent.Result.FailureType)
				nextGen = append(nextGen, child)
			}
		}
	}

	for len(nextGen) < PopulationSize {
		newStrat := nfqws.Strategy{
			Mode:    "fake",
			Repeats: 1 + rand.Intn(3),
		}
		mutator.Mutate(&newStrat)
		nextGen = append(nextGen, newStrat)
	}

	if len(nextGen) > PopulationSize {
		nextGen = nextGen[:PopulationSize]
	}

	return nextGen
}

func CalculateScore(res model.WorkerResult, complexity int, strat nfqws.Strategy) float64 {
	if res.TotalCount == 0 {
		return 0
	}

	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0
	score := successRate

	if res.SuccessCount == res.TotalCount && res.TotalCount > 0 {
		score += 50.0
	}

	// Only apply bonus if success rate is decent (>30%) to avoid "cargo cult"
	if successRate > 30.0 {
		if strings.Contains(strat.Mode, "fake") || strings.Contains(strat.Mode, "hostfake") {
			score += ScoreMaskingBonus
		}
		if strat.Fooling.BadSum {
			score += ScoreBadSumBonus
		}
	}

	penalty := float64(complexity) * 2.0
	score -= penalty

	if score < 0 {
		score = 0
	}

	return score
}
