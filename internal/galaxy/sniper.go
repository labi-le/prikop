package galaxy

import (
	"prikop/internal/model"
	"prikop/internal/nfqws"
)

// GenerateZeroGeneration создает "выстрелы" по галактике: перебор bin-файлов в разных режимах
func GenerateZeroGeneration(discoveredBins []string, report model.ReconReport) []nfqws.Strategy {
	var population []nfqws.Strategy

	// 1. Naked Checks (Базовые режимы без фейков)
	population = append(population,
		nfqws.Strategy{Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2},
		nfqws.Strategy{Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2, WSS: nfqws.WSSOptions{Enabled: true}},
	)

	// Pruning: Only add ipfrag1 if Recon confirmed it works
	if report.IPFragWorks {
		population = append(population, nfqws.Strategy{Mode: "ipfrag1", Repeats: 2})
	}

	// 2. The Sniper: Для каждого бинарника создаем прицельные стратегии
	for _, binPath := range discoveredBins {
		// Гипотеза А: Fake с этим бинарником + fooling
		// Apply BadSum if Recon confirmed it works
		foolingA := nfqws.FoolingSet{Md5Sig: true, BadSeq: true}
		if report.BadSumWorks {
			foolingA.BadSum = true
		}

		population = append(population, nfqws.Strategy{
			Mode:    "fake",
			Repeats: 4,
			Fooling: foolingA,
			Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rndsni"},
		})

		// Гипотеза B: Fake Quic (если бинарник похож на QUIC, хотя пробуем все)
		foolingB := nfqws.FoolingSet{Md5Sig: true}
		if report.BadSumWorks {
			foolingB.BadSum = true
		}

		population = append(population, nfqws.Strategy{
			Mode:    "fake",
			Repeats: 4,
			Fooling: foolingB,
			Fake:    nfqws.FakeOptions{Quic: binPath, TlsMod: "rnd"},
		})

		// Гипотеза C: Disorder/Split с этим бинарником как split-pattern (оверлей)
		population = append(population, nfqws.Strategy{
			Mode:    "multisplit",
			Repeats: 3,
			Split: nfqws.SplitOptions{
				Pos:     "2",
				SeqOvl:  336, // примерная длина ClientHello
				Pattern: binPath,
			},
		})
	}

	return population
}
