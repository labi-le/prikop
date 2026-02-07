package evolution

import (
	"math/rand"
	"prikop/internal/model"
	"strings"

	"prikop/internal/nfqws"
)

type Mutator struct {
	AvailableBins []string
}

func NewMutator(bins []string) *Mutator {
	return &Mutator{AvailableBins: bins}
}

func (m *Mutator) Mutate(s *nfqws.Strategy) {
	m.SmartMutate(s, model.ReasonNone)
}

func (m *Mutator) SmartMutate(s *nfqws.Strategy, feedback model.FailureReason) {
	r := rand.Float64()

	m.sanitize(s)

	if feedback == model.ReasonReset {
		if r < 0.6 {
			m.mutateFooling(s)
		} else if r < 0.9 {
			m.mutateTTL(s)
		} else {
			m.mutateSplit(s)
		}
		m.sanitize(s)
		return
	}

	if feedback == model.ReasonTimeout {
		if r < 0.5 {
			m.mutateFake(s)
		} else if r < 0.8 {
			m.mutateWSS(s)
		} else {
			m.mutateRepeats(s)
		}
		m.sanitize(s)
		return
	}

	if r < 0.15 {
		m.mutateMode(s)
		if s.Mode == "fake" {
			m.mutateFake(s)
		} else {
			m.mutateSplit(s)
		}
		m.sanitize(s)
		return
	}

	subR := rand.Float64()
	if s.Mode == "fake" {
		if subR < 0.4 {
			m.mutateFake(s)
		} else if subR < 0.7 {
			m.mutateFooling(s)
		} else {
			m.mutateGlobal(s)
		}
	} else {
		if subR < 0.5 {
			m.mutateSplit(s)
		} else if subR < 0.8 {
			m.mutateFooling(s)
		} else {
			m.mutateGlobal(s)
		}
	}

	m.sanitize(s)
}

func (m *Mutator) mutateGlobal(s *nfqws.Strategy) {
	r := rand.Float64()
	if r < 0.33 {
		m.mutateRepeats(s)
	} else if r < 0.66 {
		m.mutateTTL(s)
	} else {
		m.mutateWSS(s)
	}
}

// sanitize enforce strict consistency rules to prevent nfqws crashes
func (m *Mutator) sanitize(s *nfqws.Strategy) {
	isFake := s.Mode == "fake"
	isSplit := s.Mode == "multisplit" || s.Mode == "fakedsplit" || s.Mode == "multidisorder" || s.Mode == "ipfrag1"

	if !isFake {
		s.Fake = nfqws.FakeOptions{}
	} else {
		if s.Fake.TLS == "" && s.Fake.Quic == "" && len(m.AvailableBins) > 0 {
			m.mutateFake(s)
		}

		// CRITICAL FIX: Prevent "fake structure invalid" error
		// rndsni works ONLY with valid TLS ClientHello packets.
		if s.Fake.TlsMod == "rndsni" && s.Fake.TLS != "" {
			binName := strings.ToLower(s.Fake.TLS)
			// Heuristic: If binary name doesn't imply TLS, disable the mod
			if !strings.Contains(binName, "tls") && !strings.Contains(binName, "clienthello") {
				s.Fake.TlsMod = ""
			}
		}

		// Ensure we don't have dual modes active
		if s.Fake.TLS != "" && s.Fake.Quic != "" {
			// Prefer TLS slot as it's more generic
			s.Fake.Quic = ""
		}
	}

	if !isSplit {
		s.Split = nfqws.SplitOptions{}
	}

	if s.TTL.Auto > 0 || s.TTL.AutoStr != "" {
		s.TTL.Fixed = 0
		s.TTL.Fixed6 = 0
	}

	if s.Repeats < 1 {
		s.Repeats = 1
	} else if s.Repeats > 10 {
		s.Repeats = 10
	}
}

func (m *Mutator) mutateMode(s *nfqws.Strategy) {
	modes := []string{
		"fake", "fake", "fake",
		"multisplit", "multisplit",
		"multidisorder",
		"fakedsplit",
	}
	s.Mode = modes[rand.Intn(len(modes))]
}

func (m *Mutator) mutateRepeats(s *nfqws.Strategy) {
	delta := rand.Intn(3) - 1
	s.Repeats += delta
	if rand.Float64() < 0.1 {
		s.Repeats = 1 + rand.Intn(5)
	}
}

func (m *Mutator) mutateWSS(s *nfqws.Strategy) {
	if rand.Float64() < 0.3 {
		s.WSS.Enabled = !s.WSS.Enabled
	}
	if s.WSS.Enabled {
		sizes := []string{"1:6", "1:8", "1:10", "1:100", "500"}
		s.WSS.Value = sizes[rand.Intn(len(sizes))]
	}
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if len(m.AvailableBins) == 0 {
		return
	}
	bin := m.AvailableBins[rand.Intn(len(m.AvailableBins))]

	s.Fake.TLS = ""
	s.Fake.Quic = ""
	s.Fake.TlsMod = ""

	lowerBin := strings.ToLower(bin)
	isTLS := strings.Contains(lowerBin, "tls") || strings.Contains(lowerBin, "clienthello")
	isQUIC := strings.Contains(lowerBin, "quic") || strings.Contains(lowerBin, "udp")

	if isTLS {
		s.Fake.TLS = bin
		if rand.Float64() < 0.3 {
			s.Fake.TlsMod = "rndsni"
		} else if rand.Float64() < 0.3 {
			s.Fake.TlsMod = "rnd"
		} else {
			s.Fake.TlsMod = ""
		}
	} else if isQUIC {
		s.Fake.Quic = bin
		if rand.Float64() < 0.5 {
			s.Fake.TlsMod = "rnd"
		} else {
			s.Fake.TlsMod = ""
		}
	} else {
		// Fallback for unknown binaries (Wireguard, DHT, etc)
		// Safe to use in TLS slot, BUT strictly no rndsni (enforced by sanitize)
		s.Fake.TLS = bin
		s.Fake.TlsMod = ""
	}
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	positions := []string{"1", "2", "3", "1,sniext+1", "2,sniext+1", "1,midsld"}
	s.Split.Pos = positions[rand.Intn(len(positions))]

	if rand.Float64() < 0.4 {
		if rand.Intn(2) == 0 {
			s.Split.SeqOvl = 0
		} else {
			s.Split.SeqOvl = 1 + rand.Intn(500)
		}
	}

	if rand.Float64() < 0.2 && len(m.AvailableBins) > 0 {
		s.Split.Pattern = m.AvailableBins[rand.Intn(len(m.AvailableBins))]
	}
}

func (m *Mutator) mutateTTL(s *nfqws.Strategy) {
	r := rand.Float64()
	if r < 0.6 {
		s.TTL.Auto = 1 + rand.Intn(12)
		s.TTL.Fixed = 0
	} else if r < 0.9 {
		s.TTL.Fixed = 1 + rand.Intn(10)
		s.TTL.Auto = 0
	} else {
		s.TTL.Auto = 0
		s.TTL.Fixed = 0
	}
}

func (m *Mutator) mutateFooling(s *nfqws.Strategy) {
	flip := func(current bool) bool {
		if rand.Float64() < 0.2 {
			return !current
		}
		return current
	}

	s.Fooling.Md5Sig = flip(s.Fooling.Md5Sig)
	s.Fooling.BadSum = flip(s.Fooling.BadSum)
	s.Fooling.BadSeq = flip(s.Fooling.BadSeq)
	s.Fooling.Datanoack = flip(s.Fooling.Datanoack)

	if rand.Float64() < 0.1 {
		s.Fooling.HopByHop = !s.Fooling.HopByHop
		if s.Fooling.HopByHop {
			s.Fooling.HopByHop2 = false
		}
	}
}
