package galaxy

import (
	"math/rand"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"strings"
)

// GenerateZeroGeneration creates targeted strategies based on discovered bins and PROTOCOL
func GenerateZeroGeneration(discoveredBins []string, report model.ReconReport, proto string) []nfqws.Strategy {
	var population []nfqws.Strategy

	// === 1. UNIVERSAL STRATEGIES (IP Layer) ===
	if report.IPFragWorks {
		population = append(population, nfqws.Strategy{Mode: "ipfrag1", Repeats: 2})
	}

	// === 2. PROTOCOL SPECIFIC STANDARDS ===
	if proto == "tcp" {
		// HostFakeSplit - Masking + Host Spoofing
		population = append(population, nfqws.Strategy{
			Mode:    "hostfakesplit",
			Repeats: 2,
			Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
			Split:   nfqws.SplitOptions{HostMod: "host=mapgl.2gis.com", SeqOvl: 0},
		})

		// Standard Splits with basic fooling (Robust base)
		population = append(population,
			nfqws.Strategy{Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2, Fooling: nfqws.FoolingSet{BadSeq: true}},
			nfqws.Strategy{Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "2"}, Repeats: 2, Fooling: nfqws.FoolingSet{BadSeq: true}},
			nfqws.Strategy{Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2, WSS: nfqws.WSSOptions{Enabled: true}},
		)
	} else {
		// === UDP / STUN / QUIC ===

		// 1. Aggressive Fake (Good for QUIC/YouTube)
		population = append(population, nfqws.Strategy{
			Mode:    "fake",
			Repeats: 6,
			Fooling: nfqws.FoolingSet{Md5Sig: true, BadSum: report.BadSumWorks},
		})

		// 2. Safe Split (Good for streaming)
		population = append(population, nfqws.Strategy{
			Mode:    "multisplit",
			Repeats: 3,
			Split:   nfqws.SplitOptions{Pos: "1", SeqOvl: 10},
		})

		// 3. Cutoff/AnyProtocol (Good for general UDP)
		population = append(population, nfqws.Strategy{
			Mode:        "fake",
			Repeats:     4,
			AnyProtocol: true,
			Cutoff:      "d2",
			Fooling:     nfqws.FoolingSet{Md5Sig: true, BadSum: report.BadSumWorks},
		})
	}

	// === 3. THE SNIPER: BINARY TARGETING ===
	for _, binPath := range discoveredBins {
		if proto == "tcp" {
			// Hyp A: Advanced Combo
			population = append(population, nfqws.Strategy{
				Mode:    "fake,multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rnd,dupsid"},
				Split:   nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: binPath},
			})

			// Hyp D: Targeted Google/YT Pattern (The "Winner" Strategy)
			population = append(population, nfqws.Strategy{
				Mode:    "fake,multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rnd,dupsid,sni=ggpht.com"},
				Split:   nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: binPath},
			})

			// Hyp E: The "Zapret" Classic (SeqOvl 32)
			population = append(population, nfqws.Strategy{
				Mode:    "fake,multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rnd,dupsid,sni=youtube.com"},
				Split:   nfqws.SplitOptions{Pos: "2", SeqOvl: 32, Pattern: binPath},
			})

			// Hyp B: Pure Fake
			population = append(population, nfqws.Strategy{
				Mode:    "fake",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{Md5Sig: true, BadSeq: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rndsni"},
			})

			// Hyp C: RESTORED LEGACY (Pure Split)
			population = append(population, nfqws.Strategy{
				Mode:    "multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Split:   nfqws.SplitOptions{Pos: "2", SeqOvl: 336, Pattern: binPath},
			})

		} else {
			// UDP Strategy
			isSmall := strings.Contains(binPath, "zero") || strings.Contains(binPath, "512") || strings.Contains(binPath, "stun")

			if isSmall {
				// STUN Optimized: Gentle Fake
				population = append(population, nfqws.Strategy{
					Mode:    "fake",
					Repeats: 2, // Low repeats for STUN
					Fake:    nfqws.FakeOptions{UnknownUdp: binPath},
				})
			}

			// General UDP Fake
			population = append(population, nfqws.Strategy{
				Mode:        "fake",
				Repeats:     4,
				AnyProtocol: true,
				Cutoff:      "d2",
				Fooling:     nfqws.FoolingSet{Md5Sig: true, BadSum: report.BadSumWorks},
				Fake:        nfqws.FakeOptions{UnknownUdp: binPath},
			})

			// QUIC Optimized
			population = append(population, nfqws.Strategy{
				Mode:    "fake",
				Repeats: 5,
				Fooling: nfqws.FoolingSet{Md5Sig: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{Quic: binPath, TlsMod: "rnd"},
			})
		}
	}

	return population
}

// GenerateReinforcements creates specific tactical batches to break stagnation
func GenerateReinforcements(bins []string, proto string, variant int) []nfqws.Strategy {
	var reinforcement []nfqws.Strategy

	// Ensure we have bins
	var bin string
	if len(bins) > 0 {
		bin = bins[rand.Intn(len(bins))]
	}

	// Cycles: 0=MagicSplits, 1=Disorder, 2=TTL/Hop, 3=HeavyFake, 4=Masking
	cycle := variant % 5

	if proto == "tcp" {
		switch cycle {
		case 0: // Magic Splits & Combo (The most effective usually)
			magicOvls := []int{336, 620, 109, 652, 32} // Added 32
			for _, ovl := range magicOvls {
				reinforcement = append(reinforcement, nfqws.Strategy{
					Mode:    "fake,multisplit",
					Repeats: 3,
					Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: true},
					Fake:    nfqws.FakeOptions{TLS: bin, TlsMod: "rnd,dupsid"},
					Split:   nfqws.SplitOptions{Pos: "2,sld", SeqOvl: ovl, Pattern: bin},
				})
				// Variation with SNI spoof (youtube.com based on logs)
				reinforcement = append(reinforcement, nfqws.Strategy{
					Mode:    "fake,multisplit",
					Repeats: 3,
					Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: true},
					Fake:    nfqws.FakeOptions{TLS: bin, TlsMod: "rnd,dupsid,sni=youtube.com"},
					Split:   nfqws.SplitOptions{Pos: "2", SeqOvl: ovl, Pattern: bin},
				})
			}

		case 1: // Disorder
			reinforcement = append(reinforcement,
				nfqws.Strategy{Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1"}, Repeats: 2},
				nfqws.Strategy{Mode: "fakeddisorder", Split: nfqws.SplitOptions{Pos: "1", FakedPattern: bin}, Repeats: 2},
				nfqws.Strategy{Mode: "fakeddisorder", Split: nfqws.SplitOptions{Pos: "2", FakedPattern: bin}, Repeats: 2},
			)

		case 2: // TTL & HopByHop
			reinforcement = append(reinforcement,
				nfqws.Strategy{Mode: "fake", Repeats: 3, TTL: nfqws.TTLOptions{Auto: 8}, Fooling: nfqws.FoolingSet{HopByHop: true}},
				nfqws.Strategy{Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "2"}, TTL: nfqws.TTLOptions{Auto: 10}},
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 3, Fooling: nfqws.FoolingSet{HopByHop: true}},
			)

		case 3: // WSS & Heavy Fake
			reinforcement = append(reinforcement,
				nfqws.Strategy{Mode: "fake", WSS: nfqws.WSSOptions{Enabled: true, Value: "1:8"}},
				nfqws.Strategy{Mode: "fake", Fake: nfqws.FakeOptions{TLS: bin, TlsMod: "rnd,dupsid"}, Repeats: 6}, // High repeats
			)

		case 4: // Masking (HostFakeSplit variations)
			reinforcement = append(reinforcement,
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 2, Split: nfqws.SplitOptions{HostMod: "host=google.com"}},
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 2, Split: nfqws.SplitOptions{HostMod: "host=mapgl.2gis.com"}},
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 2, Split: nfqws.SplitOptions{HostMod: "host=max.ru"}},
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 2, Split: nfqws.SplitOptions{HostMod: "host=mos.ru"}},
				nfqws.Strategy{Mode: "hostfakesplit", Repeats: 3, Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: true}},
			)
		}
	} else {
		// UDP Reinforcements
		switch cycle {
		case 0: // Quic Heavy
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "fake", Repeats: 8, Fake: nfqws.FakeOptions{Quic: bin},
			})
		case 1: // Unknown UDP
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "fake", Repeats: 4, AnyProtocol: true, Cutoff: "d2", Fake: nfqws.FakeOptions{UnknownUdp: bin},
			})
		case 2: // Split UDP (rare but possible)
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "multisplit", Repeats: 3, Split: nfqws.SplitOptions{Pos: "2"},
			})
		default: // Random bin shuffle
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "fake", Repeats: 5, Fake: nfqws.FakeOptions{UnknownUdp: bin, TlsMod: "rnd"},
			})
		}
	}

	return reinforcement
}
