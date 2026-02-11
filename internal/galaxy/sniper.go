package galaxy

import (
	"math/rand"
	"prikop/internal/evolution"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"strings"
	"sync/atomic"
)

var lastSNIIdx, lastHostIdx atomic.Int32

func randSNI() string {
	pool := evolution.CommonSNIs
	for {
		idx := int32(rand.Intn(len(pool)))
		if idx != lastSNIIdx.Load() {
			lastSNIIdx.Store(idx)
			return pool[idx]
		}
	}
}

func randHost() string {
	pool := evolution.CommonHosts
	for {
		idx := int32(rand.Intn(len(pool)))
		if idx != lastHostIdx.Load() {
			lastHostIdx.Store(idx)
			return pool[idx]
		}
	}
}

// GenerateZeroGeneration creates targeted strategies based on discovered bins and PROTOCOL
func GenerateZeroGeneration(discoveredBins []string, report model.ReconReport, proto string) []nfqws.Strategy {
	var population []nfqws.Strategy

	findBin := func(mustContain string) string {
		for _, b := range discoveredBins {
			if strings.Contains(b, mustContain) {
				if proto == "tcp" && (strings.Contains(b, "dtls") || strings.Contains(b, "quic")) {
					continue
				}
				return b
			}
		}
		return ""
	}

	tlsBin := findBin("clienthello_www_google_com")
	if tlsBin == "" {
		tlsBin = findBin("clienthello")
	}

	quicBin := findBin("quic_initial_www_google_com")
	if quicBin == "" {
		quicBin = findBin("quic")
	}

	// === META STRATEGIES ===
	if proto == "tcp" {
		if tlsBin != "" {
			population = append(population, nfqws.Strategy{
				Mode: "fake,multisplit", Repeats: 2,
				Fake:  nfqws.FakeOptions{TLS: tlsBin, TlsMod: "rnd,dupsid,sni=" + randSNI()},
				Split: nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: tlsBin},
			})
			population = append(population, nfqws.Strategy{
				Mode:  "fake,fakeddisorder",
				Split: nfqws.SplitOptions{Pos: "10,midsld", SeqOvl: 336, Pattern: tlsBin, FakedPattern: tlsBin},
				Fake:  nfqws.FakeOptions{TLS: tlsBin, TlsMod: "rnd,dupsid,sni=" + randSNI()},
			})
		}
		population = append(population, nfqws.Strategy{
			Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
		})
		if tlsBin != "" {
			population = append(population, nfqws.Strategy{
				Mode: "split2", Split: nfqws.SplitOptions{SeqOvl: 681, Pattern: tlsBin},
			})
		}
		population = append(population, nfqws.Strategy{
			Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1,midsld"}, Repeats: 2,
		})
		// hostfakesplit снайперы — все SNI × разные Host, слабые умрут сами
		for i, sni := range evolution.CommonSNIs {
			population = append(population, nfqws.Strategy{
				Mode:    "fake,hostfakesplit",
				Fake:    nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=" + sni},
				Split:   nfqws.SplitOptions{HostMod: "host=" + evolution.CommonHosts[i%len(evolution.CommonHosts)]},
				Fooling: nfqws.FoolingSet{Ts: true},
				Tamper:  nfqws.TamperOptions{IpId: "zero"},
			})
		}
	} else {
		if quicBin != "" {
			population = append(population, nfqws.Strategy{
				Mode: "fake", Repeats: 4, AnyProtocol: true, Cutoff: "d2",
				Fake:    nfqws.FakeOptions{Quic: quicBin},
				Fooling: nfqws.FoolingSet{Md5Sig: true},
			})
		}
	}

	// === PROCEDURAL ===
	rand.Shuffle(len(discoveredBins), func(i, j int) {
		discoveredBins[i], discoveredBins[j] = discoveredBins[j], discoveredBins[i]
	})

	hostIdx := 0
	for _, binPath := range discoveredBins {
		if len(population) >= 100 {
			break
		}
		if proto == "tcp" {
			if strings.Contains(binPath, "dtls") || !strings.Contains(binPath, "clienthello") {
				continue
			}
			isKyber := strings.Contains(binPath, "kyber")
			population = append(population, nfqws.Strategy{
				Mode: "fake,multisplit", Repeats: 3,
				Fake: nfqws.FakeOptions{TLS: binPath, TlsMod: func() string {
					if isKyber {
						return ""
					} else {
						return "rnd,dupsid"
					}
				}()},
				Split: nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: binPath},
			})
			population = append(population, nfqws.Strategy{
				Mode: "fake,hostfakesplit", Repeats: 2,
				Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rnd,dupsid,sni=" + evolution.CommonSNIs[hostIdx%len(evolution.CommonSNIs)]},
				Split:   nfqws.SplitOptions{HostMod: "host=" + evolution.CommonHosts[hostIdx%len(evolution.CommonHosts)]},
				Fooling: nfqws.FoolingSet{Ts: true},
			})
			hostIdx++
		} else {
			if strings.Contains(binPath, "quic") {
				population = append(population, nfqws.Strategy{
					Mode: "fake", Repeats: 5,
					Fooling: nfqws.FoolingSet{Md5Sig: true},
					Fake:    nfqws.FakeOptions{Quic: binPath, TlsMod: "rnd"},
				})
			}
		}
	}

	return population
}

// GeneratePrimitives creates atomic strategies (simple blocks) to probe defenses
func GeneratePrimitives(bins []string, proto string) []nfqws.Strategy {
	var population []nfqws.Strategy

	// 1. Pure Split variants
	splitPos := []string{"1", "2", "3", "method", "host", "sld", "sniext"}
	for _, pos := range splitPos {
		population = append(population, nfqws.Strategy{
			Mode: "multisplit", Split: nfqws.SplitOptions{Pos: pos}, Repeats: 1,
		})
	}

	// 2. Pure Disorder variants
	for _, pos := range splitPos {
		population = append(population, nfqws.Strategy{
			Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: pos}, Repeats: 1,
		})
	}

	// 3. Pure Fake variants
	rand.Shuffle(len(bins), func(i, j int) { bins[i], bins[j] = bins[j], bins[i] })
	limit := 5
	if len(bins) < limit {
		limit = len(bins)
	}

	for i := 0; i < limit; i++ {
		b := bins[i]
		s := nfqws.Strategy{Mode: "fake", Repeats: 2}
		if proto == "tcp" {
			s.Fake.TLS = b
			s.Fake.TlsMod = "rnd"
		} else {
			s.Fake.Quic = b
			s.Fake.UnknownUdp = b
		}
		population = append(population, s)
	}

	// 4. TCP Specific
	if proto == "tcp" {
		population = append(population, nfqws.Strategy{Mode: "synack"})
		population = append(population, nfqws.Strategy{Mode: "syndata"})
		population = append(population, nfqws.Strategy{
			Mode: "fake", TTL: nfqws.TTLOptions{Auto: 3},
		})
	} else {
		population = append(population, nfqws.Strategy{Mode: "udplen", UdpLen: nfqws.UdpLenOptions{Increment: 2}})
	}

	return population
}

func GenerateReinforcements(bins []string, proto string, variant int) []nfqws.Strategy {
	var reinforcement []nfqws.Strategy
	findBin := func(sub string) string {
		for _, b := range bins {
			if strings.Contains(b, sub) {
				return b
			}
		}
		return ""
	}
	tlsBin := findBin("clienthello_www_google_com")

	if proto == "tcp" && tlsBin != "" {
		switch variant % 5 {
		case 0:
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "fakeddisorder", Fooling: nfqws.FoolingSet{Md5Sig: true},
				Dup:   nfqws.DupOptions{Count: 1, Cutoff: "n2", Fooling: "md5sig"},
				Split: nfqws.SplitOptions{Pos: "method+2"},
			})
		case 1:
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "fake,fakedsplit", Repeats: 6, Fooling: nfqws.FoolingSet{Ts: true},
				Split:  nfqws.SplitOptions{FakedPattern: "0x12"},
				Fake:   nfqws.FakeOptions{TLS: tlsBin},
				Tamper: nfqws.TamperOptions{IpId: "zero"},
			})
		case 2:
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
			})
		case 3:
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "2,5,105,host+5,sld-1,endsld-5,endsld"},
			})
		case 4:
			reinforcement = append(reinforcement, nfqws.Strategy{
				Mode:    "fake,hostfakesplit",
				Fake:    nfqws.FakeOptions{TLS: tlsBin, TlsMod: "rnd,dupsid,sni=www.google.com"},
				Split:   nfqws.SplitOptions{HostMod: "host=www.google.com"},
				Fooling: nfqws.FoolingSet{Ts: true},
				Tamper:  nfqws.TamperOptions{IpId: "zero"},
			})
		}
	}
	return reinforcement
}
