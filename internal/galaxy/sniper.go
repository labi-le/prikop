package galaxy

import (
	"math/rand"
	"prikop/internal/evolution"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"sort"
	"strings"
)

// GenerateZeroGeneration creates targeted strategies based on discovered bins and PROTOCOL
func GenerateZeroGeneration(discoveredBins []string, report model.ReconReport, proto string) []nfqws.Strategy {
	tlsBins, quicBins := findRelevantBins(discoveredBins, proto)
	var population []nfqws.Strategy

	if report.BadSumWorks {
		population = append(population, nfqws.Strategy{
			Mode: "fake", Repeats: 2,
			Fooling: nfqws.FoolingSet{BadSum: true},
		})
		population = append(population, nfqws.Strategy{
			Mode: "fake,multidisorder", Repeats: 2,
			Fooling: nfqws.FoolingSet{BadSum: true},
			Split:   nfqws.SplitOptions{Pos: "1,sniext"},
		})
	}
	if report.IPFragWorks {
		population = append(population, nfqws.Strategy{
			Mode: "ipfrag1", Repeats: 2,
		})
	}

	if proto == "tcp" {
		// 1. Import Known High-Efficacy Strategies (Yv Series)
		population = append(population, generateImportedStrategies(discoveredBins)...)
		// 2. Generate content-dependent strategies
		population = append(population, generateTCPBinDependent(tlsBins)...)
		// 3. Generate static strategies
		population = append(population, generateTCPStatic()...)
	} else {
		population = append(population, generateUDPBinDependent(quicBins)...)
	}

	// 4. Procedural fillers
	population = append(population, generateProcedural(discoveredBins, proto)...)

	return population
}

func findRelevantBins(bins []string, proto string) ([]string, []string) {
	var tlsBins, quicBins []string

	for _, b := range bins {
		if proto == "tcp" {
			if strings.Contains(b, "dtls") || strings.Contains(b, "quic") {
				continue
			}
			if strings.Contains(b, "clienthello") {
				tlsBins = append(tlsBins, b)
			}
		} else {
			if strings.Contains(b, "quic") {
				quicBins = append(quicBins, b)
			}
		}
	}

	sortPriority := func(slice []string, keyword string) {
		sort.Slice(slice, func(i, j int) bool {
			hasKeyI := strings.Contains(slice[i], keyword)
			hasKeyJ := strings.Contains(slice[j], keyword)
			if hasKeyI && !hasKeyJ {
				return true
			}
			if !hasKeyI && hasKeyJ {
				return false
			}
			return slice[i] < slice[j]
		})
	}

	sortPriority(tlsBins, "google")
	sortPriority(quicBins, "google")

	return tlsBins, quicBins
}

func generateImportedStrategies(bins []string) []nfqws.Strategy {
	find := func(name string) string {
		for _, b := range bins {
			if strings.HasSuffix(b, name) {
				return b
			}
		}
		return ""
	}

	googleClientHello := find("tls_clienthello_www_google_com.bin")

	var s []nfqws.Strategy

	// Yv01
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:   "multisplit",
			Tamper: nfqws.TamperOptions{IpId: "zero"},
			Split:  nfqws.SplitOptions{Pos: "1", SeqOvl: 681, Pattern: googleClientHello},
		})
	}

	// Yv02
	s = append(s, nfqws.Strategy{
		Mode:  "multisplit",
		Split: nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
	})

	// Yv03
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,multisplit",
			Split:   nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: googleClientHello},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello, TlsMod: "rnd,dupsid,sni=ggpht.com"},
			Fooling: nfqws.FoolingSet{BadSum: true, BadSeq: true},
		})
	}

	// Yv04
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:  "split2",
			Split: nfqws.SplitOptions{SeqOvl: 681, Pattern: googleClientHello},
		})
	}

	// Yv05
	gosuslugiClientHello := find("tls_clienthello_gosuslugi_ru.bin")
	vkClientHello := find("tls_clienthello_vk_com.bin")
	if googleClientHello != "" && vkClientHello != "" && gosuslugiClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode: "fake,fakeddisorder",
			Split: nfqws.SplitOptions{
				Pos:          "10,midsld",
				SeqOvl:       336,
				Pattern:      gosuslugiClientHello,
				FakedPattern: vkClientHello,
			},
			Fake:    nfqws.FakeOptions{TLS: "0x0F0F0F0F", TlsMod: "none"},
			Fooling: nfqws.FoolingSet{BadSeq: true, BadSum: true, BadSeqIncrement: 0},
		})
	}

	// Yv06
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "multidisorder",
			Split:   nfqws.SplitOptions{Pos: "7,sld+1"},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello, TlsMod: "rnd,dupsid,sni=www.google.com"},
			Fooling: nfqws.FoolingSet{BadSeq: true},
			TTL:     nfqws.TTLOptions{AutoStr: "2:2-12"},
		})
	}

	// Yv07
	s = append(s, nfqws.Strategy{
		Mode:    "multidisorder",
		Split:   nfqws.SplitOptions{Pos: "1,midsld,endhost-1"},
		Repeats: 2,
		Fooling: nfqws.FoolingSet{Md5Sig: true},
		Fake:    nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=www.google.com"},
	})

	// Yv08
	s = append(s, nfqws.Strategy{
		Mode:    "fake,multisplit",
		Fake:    nfqws.FakeOptions{TLS: "!", TlsMod: "rnd,dupsid,sni=www.google.com"},
		Split:   nfqws.SplitOptions{Pos: "1,midsld"},
		Repeats: 2,
		Fooling: nfqws.FoolingSet{BadSeq: true},
	})

	// Yv09
	googleQuicInitial := find("quic_initial_www_google_com.bin")
	if googleQuicInitial != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "multidisorder",
			Split:   nfqws.SplitOptions{Pos: "1,midsld"},
			Repeats: 6,
			Fooling: nfqws.FoolingSet{BadSeq: true, BadSeqIncrement: 2},
			Fake:    nfqws.FakeOptions{Quic: googleQuicInitial},
		})
	}

	// Yv10
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:  "multisplit",
			Split: nfqws.SplitOptions{Pos: "1,2", SeqOvl: 4, Pattern: googleClientHello},
			Fake:  nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=www.google.com"},
		})
	}

	// Yv11
	s = append(s, nfqws.Strategy{
		Mode:  "multidisorder",
		Split: nfqws.SplitOptions{Pos: "2,5,105,host+5,sld-1,endsld-5,endsld"},
	})

	// Yv12
	s = append(s, nfqws.Strategy{
		Mode:    "multidisorder",
		Split:   nfqws.SplitOptions{Pos: "1,midsld"},
		Repeats: 2,
	})

	// Yv13
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,multidisorder",
			Split:   nfqws.SplitOptions{Pos: "1", SeqOvl: 681, Pattern: googleClientHello},
			Fake:    nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=fonts.google.com"},
			Repeats: 2,
			Fooling: nfqws.FoolingSet{BadSeq: true, BadSeqIncrement: 10000000},
		})
	}

	// Yv14
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,multidisorder",
			Split:   nfqws.SplitOptions{Pos: "10,midsld", SeqOvl: 336, Pattern: googleClientHello},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello, TlsMod: "rnd,dupsid,sni=fonts.google.com"},
			Fooling: nfqws.FoolingSet{BadSeq: true},
		})
	}

	// Yv15
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,multisplit",
			Split:   nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 2108, Pattern: googleClientHello},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello, TlsMod: "rnd,dupsid,sni=ggpht.com"},
			Fooling: nfqws.FoolingSet{BadSum: true, BadSeq: true},
		})
	}

	// Yv16
	s = append(s, nfqws.Strategy{
		Mode:    "multisplit",
		Split:   nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
		Fooling: nfqws.FoolingSet{BadSum: true, BadSeq: true, BadSeqIncrement: 0},
	})

	// Yv17
	s = append(s, nfqws.Strategy{
		Mode:    "fakeddisorder",
		Split:   nfqws.SplitOptions{Pos: "method+2"},
		Fooling: nfqws.FoolingSet{Md5Sig: true},
		Dup:     nfqws.DupOptions{Count: 1, Cutoff: "n2", Fooling: "md5sig"},
	})

	// Yv18
	s = append(s, nfqws.Strategy{
		Mode:    "fake,hostfakesplit",
		Fake:    nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=www.google.com"},
		Split:   nfqws.SplitOptions{HostMod: "host=www.google.com,altorder=1"},
		Fooling: nfqws.FoolingSet{Ts: true},
		Tamper:  nfqws.TamperOptions{IpId: "zero"},
	})

	// Yv19
	s = append(s, nfqws.Strategy{
		Mode:    "hostfakesplit",
		Split:   nfqws.SplitOptions{HostMod: "host=google.com"},
		Fooling: nfqws.FoolingSet{Ts: true},
	})

	// Yv20
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,fakedsplit",
			Repeats: 6,
			Fooling: nfqws.FoolingSet{Ts: true},
			Tamper:  nfqws.TamperOptions{IpId: "zero"},
			Split:   nfqws.SplitOptions{FakedPattern: "0x00"},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello},
		})
	}

	// Yv21
	if googleClientHello != "" {
		s = append(s, nfqws.Strategy{
			Mode:    "fake,multisplit",
			Repeats: 8,
			Fooling: nfqws.FoolingSet{Ts: true},
			Tamper:  nfqws.TamperOptions{IpId: "zero"},
			Split:   nfqws.SplitOptions{Pos: "1", SeqOvl: 681, Pattern: googleClientHello},
			Fake:    nfqws.FakeOptions{TLS: googleClientHello},
		})
	}

	return s
}

func generateTCPBinDependent(tlsBins []string) []nfqws.Strategy {
	var strategies []nfqws.Strategy

	snis := evolution.CommonSNIs

	for i, bin := range tlsBins {
		sni := snis[i%len(snis)]

		strategies = append(strategies, nfqws.Strategy{
			Mode: "fake,multisplit", Repeats: 2,
			Fake:  nfqws.FakeOptions{TLS: bin, TlsMod: "rnd,dupsid,sni=" + sni},
			Split: nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: bin},
		})
		strategies = append(strategies, nfqws.Strategy{
			Mode:  "fake,fakeddisorder",
			Split: nfqws.SplitOptions{Pos: "10,midsld", SeqOvl: 336, Pattern: bin, FakedPattern: bin},
			Fake:  nfqws.FakeOptions{TLS: bin, TlsMod: "rnd,dupsid,sni=" + sni},
		})
	}
	return strategies
}

func generateTCPStatic() []nfqws.Strategy {
	var strategies []nfqws.Strategy

	strategies = append(strategies, nfqws.Strategy{
		Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
	})

	strategies = append(strategies, nfqws.Strategy{
		Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "1,midsld"}, Repeats: 2,
	})

	// Static hostfakesplit: independent of bin content
	// Iterates ALL common SNIs/Hosts
	for i, sni := range evolution.CommonSNIs {
		host := evolution.CommonHosts[i%len(evolution.CommonHosts)]
		strategies = append(strategies, nfqws.Strategy{
			Mode:    "fake,hostfakesplit",
			Fake:    nfqws.FakeOptions{TlsMod: "rnd,dupsid,sni=" + sni},
			Split:   nfqws.SplitOptions{HostMod: "host=" + host},
			Fooling: nfqws.FoolingSet{Ts: true},
			Tamper:  nfqws.TamperOptions{IpId: "zero"},
		})
	}
	return strategies
}

func generateUDPBinDependent(quicBins []string) []nfqws.Strategy {
	var strategies []nfqws.Strategy
	for _, bin := range quicBins {
		strategies = append(strategies, nfqws.Strategy{
			Mode: "fake", Repeats: 4, AnyProtocol: true, Cutoff: "d2",
			Fake:    nfqws.FakeOptions{Quic: bin},
			Fooling: nfqws.FoolingSet{Md5Sig: true},
		})
	}
	return strategies
}

func generateProcedural(discoveredBins []string, proto string) []nfqws.Strategy {
	var strategies []nfqws.Strategy

	// Soft limit to prevent OOM if bins count is huge
	limit := 150

	bins := make([]string, len(discoveredBins))
	copy(bins, discoveredBins)
	rand.Shuffle(len(bins), func(i, j int) {
		bins[i], bins[j] = bins[j], bins[i]
	})

	for _, binPath := range bins {
		if len(strategies) >= limit {
			break
		}
		if proto == "tcp" {
			strategies = append(strategies, generateTCPProcedural(binPath)...)
		} else {
			strategies = append(strategies, generateUDPProcedural(binPath)...)
		}
	}
	return strategies
}

// generateTCPProcedural now returns a strategy for EVERY common host
func generateTCPProcedural(binPath string) []nfqws.Strategy {
	if strings.Contains(binPath, "dtls") || !strings.Contains(binPath, "clienthello") {
		return nil
	}
	var strategies []nfqws.Strategy
	isKyber := strings.Contains(binPath, "kyber")

	tlsMod := "rnd,dupsid"
	if isKyber {
		tlsMod = ""
	}

	// 1. Generic Payload Strategy (One per bin)
	strategies = append(strategies, nfqws.Strategy{
		Mode: "fake,multisplit", Repeats: 3,
		Fake:  nfqws.FakeOptions{TLS: binPath, TlsMod: tlsMod},
		Split: nfqws.SplitOptions{Pos: "2,sld", SeqOvl: 620, Pattern: binPath},
	})

	// 2. Host-Specific Strategies (One per Host in CommonHosts)
	// This attempts to find the magic combination of "Valid Payload (Bin)" + "Valid Host Header"
	for i, host := range evolution.CommonHosts {
		sni := evolution.CommonSNIs[i%len(evolution.CommonSNIs)]
		strategies = append(strategies, nfqws.Strategy{
			Mode: "fake,hostfakesplit", Repeats: 2,
			Fake:    nfqws.FakeOptions{TLS: binPath, TlsMod: "rnd,dupsid,sni=" + sni},
			Split:   nfqws.SplitOptions{HostMod: "host=" + host},
			Fooling: nfqws.FoolingSet{Ts: true},
		})
	}

	return strategies
}

func generateUDPProcedural(binPath string) []nfqws.Strategy {
	if strings.Contains(binPath, "quic") {
		return []nfqws.Strategy{{
			Mode: "fake", Repeats: 5,
			Fooling: nfqws.FoolingSet{Md5Sig: true},
			Fake:    nfqws.FakeOptions{Quic: binPath, TlsMod: "rnd"},
		}}
	}
	return nil
}

func GeneratePrimitives(bins []string, proto string) []nfqws.Strategy {
	var population []nfqws.Strategy
	population = append(population, generateSimplePrimitives("multisplit")...)
	population = append(population, generateSimplePrimitives("multidisorder")...)
	population = append(population, generateFakePrimitives(bins, proto)...)
	population = append(population, generateProtoSpecific(proto)...)
	return population
}

func generateSimplePrimitives(mode string) []nfqws.Strategy {
	var strategies []nfqws.Strategy
	splitPos := []string{"1", "2", "3", "method", "host", "sld", "sniext"}
	for _, pos := range splitPos {
		strategies = append(strategies, nfqws.Strategy{
			Mode: mode, Split: nfqws.SplitOptions{Pos: pos}, Repeats: 1,
		})
	}
	return strategies
}

func generateFakePrimitives(bins []string, proto string) []nfqws.Strategy {
	var strategies []nfqws.Strategy
	shuffled := make([]string, len(bins))
	copy(shuffled, bins)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	limit := 5
	if len(shuffled) < limit {
		limit = len(shuffled)
	}

	for i := 0; i < limit; i++ {
		b := shuffled[i]
		s := nfqws.Strategy{Mode: "fake", Repeats: 2}
		if proto == "tcp" {
			s.Fake.TLS = b
			s.Fake.TlsMod = "rnd"
		} else {
			s.Fake.Quic = b
			s.Fake.UnknownUdp = b
		}
		strategies = append(strategies, s)
	}
	return strategies
}

func generateProtoSpecific(proto string) []nfqws.Strategy {
	if proto == "tcp" {
		return []nfqws.Strategy{
			{Mode: "synack"},
			{Mode: "syndata"},
			{Mode: "fake", TTL: nfqws.TTLOptions{Auto: 3}},
		}
	}
	return []nfqws.Strategy{
		{Mode: "udplen", UdpLen: nfqws.UdpLenOptions{Increment: 2}},
	}
}

func GenerateReinforcements(bins []string, proto string, variant int) []nfqws.Strategy {
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
		return generateTCPReinforcements(tlsBin, variant%5)
	}
	return nil
}

func generateTCPReinforcements(tlsBin string, caseIdx int) []nfqws.Strategy {
	switch caseIdx {
	case 0:
		return []nfqws.Strategy{{
			Mode: "fakeddisorder", Fooling: nfqws.FoolingSet{Md5Sig: true},
			Dup:   nfqws.DupOptions{Count: 1, Cutoff: "n2", Fooling: "md5sig"},
			Split: nfqws.SplitOptions{Pos: "method+2"},
		}}
	case 1:
		return []nfqws.Strategy{{
			Mode: "fake,fakedsplit", Repeats: 6, Fooling: nfqws.FoolingSet{Ts: true},
			Split:  nfqws.SplitOptions{FakedPattern: "0x12"},
			Fake:   nfqws.FakeOptions{TLS: tlsBin},
			Tamper: nfqws.TamperOptions{IpId: "zero"},
		}}
	case 2:
		return []nfqws.Strategy{{
			Mode: "multisplit", Split: nfqws.SplitOptions{Pos: "1,sniext+1", SeqOvl: 1},
		}}
	case 3:
		return []nfqws.Strategy{{
			Mode: "multidisorder", Split: nfqws.SplitOptions{Pos: "2,5,105,host+5,sld-1,endsld-5,endsld"},
		}}
	case 4:
		return []nfqws.Strategy{{
			Mode:    "fake,hostfakesplit",
			Fake:    nfqws.FakeOptions{TLS: tlsBin, TlsMod: "rnd,dupsid,sni=www.google.com"},
			Split:   nfqws.SplitOptions{HostMod: "host=www.google.com"},
			Fooling: nfqws.FoolingSet{Ts: true},
			Tamper:  nfqws.TamperOptions{IpId: "zero"},
		}}
	}
	return nil
}
