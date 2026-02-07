package evolution

import (
	"fmt"
	"math/rand"
	"sort"

	"prikop/internal/model"
	"prikop/internal/nfqws"
)

const (
	PopulationSize = 100
)

// Evolve принимает результаты прошлого поколения и возвращает новое.
// Использует Tournament Selection с кластеризацией для сохранения разнообразия.
func Evolve(results []model.ScoredStrategy, discoveredBins []string) []nfqws.Strategy {
	var nextGen []nfqws.Strategy
	mutator := NewMutator(discoveredBins)

	clusters := make(map[string][]model.ScoredStrategy)

	for _, r := range results {
		strat, ok := r.Config.(nfqws.Strategy)
		if !ok {
			continue
		}
		key := strat.Mode
		if strat.Mode == "fake" {
			// Различаем fake-tls и fake-quic
			if strat.Fake.Quic != "" {
				key += "-quic"
			} else {
				key += "-tls"
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
			return CalculateScore(cluster[i].Result, cluster[i].Complexity) >
				CalculateScore(cluster[j].Result, cluster[j].Complexity)
		})

		// Берем топ-1, это Элита кластера
		bestParents = append(bestParents, cluster[0])

		// Сохраняем элиту в новое поколение без изменений
		if s, ok := cluster[0].Config.(nfqws.Strategy); ok {
			nextGen = append(nextGen, s)
		}

		// Если кластер большой и успешный, берем еще пару родителей
		if len(cluster) > 3 && cluster[0].Result.SuccessCount > 0 {
			bestParents = append(bestParents, cluster[1], cluster[2])
		}
	}

	// 3. Breeding with Feedback
	// Заполняем популяцию мутантами от лучших родителей
	slotsRemaining := PopulationSize - len(nextGen)

	// Если родителей слишком мало, добиваем Fresh Blood позже
	if len(bestParents) > 0 {
		for i := 0; i < slotsRemaining; i++ {
			// Roulette Wheel selection among best parents could be better,
			// but Random pick is fine for now given we pre-filtered bestParents
			parent := bestParents[rand.Intn(len(bestParents))]

			if s, ok := parent.Config.(nfqws.Strategy); ok {
				child := s

				// CRITICAL: Используем причину сбоя родителя для направленной мутации
				// Если родитель был успешен частично (SuccessCount > 0), FailureType может быть пустым.
				// В таком случае SmartMutate сделает "fine tuning".
				mutator.SmartMutate(&child, parent.Result.FailureType)

				nextGen = append(nextGen, child)
			}
		}
	}

	// 4. Emergency Fill (Fresh Blood)
	// Если стратегий все еще мало (или все родители умерли)
	for len(nextGen) < PopulationSize {
		newStrat := nfqws.Strategy{
			Mode:    "fake",
			Repeats: 1 + rand.Intn(4),
		}
		mutator.Mutate(&newStrat) // Полный рандом
		nextGen = append(nextGen, newStrat)
	}

	// Обрезка на всякий случай
	if len(nextGen) > PopulationSize {
		nextGen = nextGen[:PopulationSize]
	}

	return nextGen
}

func CalculateScore(res model.WorkerResult, complexity int) float64 {
	if res.TotalCount == 0 {
		return 0
	}

	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0

	// Огромный бонус за 100% успех
	if res.SuccessCount == res.TotalCount {
		successRate += 50.0
	}

	// Штраф за сложность (repeats)
	penalty := float64(complexity) * 2.0 // Увеличили штраф, чтобы при прочих равных выбирал меньше repeats

	return successRate - penalty
}
