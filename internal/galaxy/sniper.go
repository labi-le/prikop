package galaxy

import (
	"prikop/internal/nfqws"
)

// GenerateZeroGeneration создает "выстрелы" по галактике: перебор bin-файлов в разных режимах
func GenerateZeroGeneration(discoveredBins []string) []nfqws.Strategy {
	var population []nfqws.Strategy

	// 1. Naked Checks (Базовые режимы без фейков)
	population = append(population,
		nfqws.Strategy{Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2},
		nfqws.Strategy{Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2, WSS: nfqws.WSSOptions{Enabled: true}},
		nfqws.Strategy{Mode: "ipfrag1", Repeats: 2},
	)

	// 2. The Sniper: Для каждого бинарника создаем прицельные стратегии
	for _, binPath := range discoveredBins {
		// Гипотеза А: Fake с этим бинарником + fooling
		population = append(population, nfqws.Strategy{
			Mode:    "fake",
			Repeats: 4,
			Fooling: nfqws.FoolingSet{Md5Sig: true, BadSeq: true},
			Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rndsni"},
		})

		// Гипотеза B: Fake Quic (если бинарник похож на QUIC, хотя пробуем все)
		population = append(population, nfqws.Strategy{
			Mode:    "fake",
			Repeats: 4,
			Fooling: nfqws.FoolingSet{Md5Sig: true},
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
