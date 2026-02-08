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
	ScoreMaskingBonus = 15.0
	// Штрафы за "грязные" методы, которые ломаются за NAT
	PenaltyBadSum = 20.0
	PenaltyBadSeq = 10.0

	IdealScoreBonus   = 50.0
	RobustSuccessRate = 30.0
	ComplexityWeight  = 0.5

	ChaosTCPFakeMultiSplitProbability    = 0.20
	ChaosTCPFakeMultiDisorderProbability = 0.40
	ChaosTCPMultiSplitProbability        = 0.60
	ChaosTCPMultiDisorderProbability     = 0.80
	ChaosUDPUDPLenProbability            = 0.50

	ChaosMinMutations   = 2
	ChaosExtraMutations = 3

	SurvivorSuccessThreshold = 0
	ClusterMinSizeForBackup  = 3
)

func Evolve(results []model.ScoredStrategy, discoveredBins []string, proto string) []nfqws.Strategy {
	var nextGen []nfqws.Strategy
	mutator := NewMutator(discoveredBins, proto)

	// 1. ЖЕСТКИЙ ФИЛЬТР: Выживают только те, кто хоть что-то пробил.
	var survivors []model.ScoredStrategy
	for _, r := range results {
		if r.Result.SuccessCount > SurvivorSuccessThreshold {
			survivors = append(survivors, r)
		}
	}

	// === ЭВОЛЮЦИОННОЕ СПАСЕНИЕ ===
	// Если никто не выжил (Success == 0), ищем тех, кто сломал логику DPI (вызвал Timeout вместо Reset).
	// Timeout означает, что DPI "завис" или дропнул пакет, не сумев распознать запрос. Это шаг к победе.
	if len(survivors) == 0 {
		foundTimeouts := false
		for _, r := range results {
			if r.Result.FailureType == model.ReasonTimeout {
				survivors = append(survivors, r)
				foundTimeouts = true
			}
		}
		if foundTimeouts {
			fmt.Printf("    [!] [%s] No direct survivors. Salvaged strategies that caused DPI Timeout (Confusion).\n", strings.ToUpper(proto))
		}
	}

	// 2. EXTINCTION EVENT -> CHAOS MODE
	// Если даже Timeout-стратегий нет, запускаем Хаос
	if len(survivors) == 0 {
		fmt.Printf("    [!] [%s] EXTINCTION: No strategies survived. Spawning Chaos Generation.\n", strings.ToUpper(proto))
		return generateChaos(mutator, PopulationSize, proto)
	}

	// 3. Кластеризация (чтобы не размножать одно и то же)
	clusters := make(map[string][]model.ScoredStrategy)
	for _, r := range survivors {
		strat, ok := r.Config.(nfqws.Strategy)
		if !ok {
			continue
		}
		// Группируем по Mode и позиции Split, чтобы сохранить разнообразие видов
		key := strat.Mode
		if strings.Contains(strat.Mode, "split") || strings.Contains(strat.Mode, "disorder") {
			key += "|" + strat.Split.Pos
		}
		clusters[key] = append(clusters[key], r)
	}

	fmt.Printf("    [i] [%s] Diversity: %d unique working architectures survived.\n", strings.ToUpper(proto), len(clusters))

	var bestParents []model.ScoredStrategy

	// Отбираем лучших представителей каждого кластера
	for _, cluster := range clusters {
		sort.Slice(cluster, func(i, j int) bool {
			s1, _ := cluster[i].Config.(nfqws.Strategy)
			s2, _ := cluster[j].Config.(nfqws.Strategy)
			return CalculateScore(cluster[i].Result, cluster[i].Complexity, s1) >
				CalculateScore(cluster[j].Result, cluster[j].Complexity, s2)
		})

		// Лучший идет в родители и в следующее поколение
		bestParents = append(bestParents, cluster[0])
		if s, ok := cluster[0].Config.(nfqws.Strategy); ok {
			nextGen = append(nextGen, s)
		}

		// Если стратегия идеальна (100% успех), берем и второго лучшего (backup)
		if len(cluster) > ClusterMinSizeForBackup && cluster[0].Result.SuccessCount == cluster[0].Result.TotalCount {
			if s, ok := cluster[1].Config.(nfqws.Strategy); ok {
				nextGen = append(nextGen, s)
			}
		}
	}

	// 4. Breeding (Размножение с мутациями)
	slotsRemaining := PopulationSize - len(nextGen)
	if slotsRemaining < 0 {
		slotsRemaining = 0
	}

	if len(bestParents) > 0 {
		for i := 0; i < slotsRemaining; i++ {
			// Случайный родитель из лучших
			parent := bestParents[rand.Intn(len(bestParents))]
			if s, ok := parent.Config.(nfqws.Strategy); ok {
				child := s
				// Умная мутация на основе причины смерти родителя
				mutator.SmartMutate(&child, parent.Result.FailureType)
				nextGen = append(nextGen, child)
			}
		}
	} else {
		// Fallback (на всякий случай)
		return generateChaos(mutator, PopulationSize, proto)
	}

	// Обрезка популяции
	if len(nextGen) > PopulationSize {
		nextGen = nextGen[:PopulationSize]
	}

	return nextGen
}

// generateChaos создает стратегии с повышенным шансом на сложные методы
func generateChaos(m *Mutator, count int, proto string) []nfqws.Strategy {
	var population []nfqws.Strategy
	for i := 0; i < count; i++ {
		s := nfqws.Strategy{Repeats: 1 + rand.Intn(3)}
		r := rand.Float64()

		if proto == "tcp" {
			// Распределение вероятностей для TCP
			if r < ChaosTCPFakeMultiSplitProbability {
				s.Mode = "fake,multisplit"
			} else if r < ChaosTCPFakeMultiDisorderProbability {
				s.Mode = "fake,multidisorder"
			} else if r < ChaosTCPMultiSplitProbability {
				s.Mode = "multisplit" // Чистый сплит (иногда фейки палятся)
			} else if r < ChaosTCPMultiDisorderProbability {
				s.Mode = "multidisorder"
			} else {
				// Резервный сложный метод
				s.Mode = "hostfakesplit"
				s.Split.HostMod = "host=www.google.com"
			}
		} else {
			// UDP/QUIC
			if r < ChaosUDPUDPLenProbability {
				s.Mode = "fake"
			} else {
				s.Mode = "udplen"
			}
		}

		// Принудительные множественные мутации для создания уникального генома
		mutations := ChaosMinMutations + rand.Intn(ChaosExtraMutations)
		for j := 0; j < mutations; j++ {
			m.Mutate(&s)
		}

		// Обязательная санитарная обработка
		m.sanitize(&s)

		population = append(population, s)
	}
	return population
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
