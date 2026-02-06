package evolution

import (
	"math/rand"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"sort"
	"time"
)

const (
	PopulationSize = 50
	ElitesCount    = 5
)

// Evolve принимает результаты прошлого поколения и возвращает новое строго фиксированного размера
func Evolve(results []model.ScoredStrategy, discoveredBins []string) []nfqws.Strategy {
	var nextGen []nfqws.Strategy
	rand.Seed(time.Now().UnixNano())
	mutator := NewMutator(discoveredBins)

	// 1. Сортировка (на всякий случай, если оркестратор не отсортировал)
	sort.Slice(results, func(i, j int) bool {
		return CalculateScore(results[i].Result, results[i].Complexity) >
			CalculateScore(results[j].Result, results[j].Complexity)
	})

	// 2. Elitism: Сохраняем лучших без изменений
	for i := 0; i < len(results) && i < ElitesCount; i++ {
		if s, ok := results[i].Config.(nfqws.Strategy); ok {
			nextGen = append(nextGen, s)
		}
	}

	// 3. Adaptive Mutation: Мутируем лучших
	// Берем топ-10 (или меньше) для мутаций
	breedPoolSize := 10
	if len(results) < breedPoolSize {
		breedPoolSize = len(results)
	}

	for i := 0; i < breedPoolSize; i++ {
		parent, ok := results[i].Config.(nfqws.Strategy)
		if !ok {
			continue
		}
		// Создаем мутантов пока есть место, но не более 3 на родителя
		for k := 0; k < 3; k++ {
			child := parent
			mutator.Mutate(&child)
			nextGen = append(nextGen, child)
		}
	}

	// 4. Crossover: Скрещивание
	if len(results) >= 2 {
		for i := 0; i < 10; i++ {
			idx1 := rand.Intn(breedPoolSize)
			idx2 := rand.Intn(breedPoolSize)

			p1, ok1 := results[idx1].Config.(nfqws.Strategy)
			p2, ok2 := results[idx2].Config.(nfqws.Strategy)

			if ok1 && ok2 {
				child := p1
				// Скрещиваем параметры Fake и TTL
				child.Fake = p2.Fake
				child.TTL = p2.TTL
				// Шанс мутации ребенка
				if rand.Float64() < 0.3 {
					mutator.Mutate(&child)
				}
				nextGen = append(nextGen, child)
			}
		}
	}

	// 5. Population Control: Truncate or Fill
	// Если перебор - обрезаем
	if len(nextGen) > PopulationSize {
		nextGen = nextGen[:PopulationSize]
	}

	// Если недобор - заполняем случайными стратегиями (Fresh Blood)
	for len(nextGen) < PopulationSize {
		newStrat := nfqws.Strategy{
			Mode:    "fake",
			Repeats: 1 + rand.Intn(5),
		}
		mutator.Mutate(&newStrat) // Полная рандомизация
		nextGen = append(nextGen, newStrat)
	}

	return nextGen
}

func CalculateScore(res model.WorkerResult, complexity int) float64 {
	if res.TotalCount == 0 {
		return 0
	}
	// Приоритет: SuccessRate > Code 200 > Low Complexity
	successRate := (float64(res.SuccessCount) / float64(res.TotalCount)) * 100.0

	// Штраф за сложность (repeats) минимален, но важен при равных успехах
	penalty := float64(complexity) * 0.1

	return successRate - penalty
}
