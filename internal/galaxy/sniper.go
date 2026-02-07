package galaxy

import (
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

			// Hyp B: Pure Fake
			population = append(population, nfqws.Strategy{
				Mode:    "fake",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{Md5Sig: true, BadSeq: true, BadSum: report.BadSumWorks},
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rndsni"},
			})

			// Hyp C: RESTORED LEGACY (Pure Split)
			// Variation 1: Pos 2 (Classic)
			population = append(population, nfqws.Strategy{
				Mode:    "multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Split: nfqws.SplitOptions{
					Pos:     "2",
					SeqOvl:  336,
					Pattern: binPath,
				},
			})
			// Variation 2: Pos 1 (Aggressive Start)
			population = append(population, nfqws.Strategy{
				Mode:    "multisplit",
				Repeats: 3,
				Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: report.BadSumWorks},
				Split: nfqws.SplitOptions{
					Pos:     "1",
					SeqOvl:  109,
					Pattern: binPath,
				},
			})

		} else {
			// UDP Strategy
			isSmall := strings.Contains(binPath, "zero") || strings.Contains(binPath, "512") || strings.Contains(binPath, "stun")

			if isSmall {
				// STUN Optimized: Gentle Fake
				// Low repeats, no checksum tampering if possible, relies on payload content
				population = append(population, nfqws.Strategy{
					Mode:    "fake",
					Repeats: 2, // Low repeats for STUN
					Fake:    nfqws.FakeOptions{UnknownUdp: binPath},
					// No fooling flags intentionally to avoid dropping by strict NATs
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
