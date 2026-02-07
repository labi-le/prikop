package evolution

import (
	"math/rand"
	"strings"

	"prikop/internal/nfqws"
)

type Mutator struct {
	AvailableBins []string
}

func NewMutator(bins []string) *Mutator {
	return &Mutator{AvailableBins: bins}
}

// Mutate implements Grammar-Based Fuzzing (Constraint Enforcement).
func (m *Mutator) Mutate(s *nfqws.Strategy) {
	r := rand.Float64()

	// 1. Structure Mutation (20%)
	if r < 0.20 {
		m.mutateMode(s)
		m.sanitize(s)
		return
	}

	// 2. Parameter Tuning (40%)
	if r < 0.60 {
		if s.Mode == "fake" {
			m.mutateFake(s)
		} else {
			m.mutateSplit(s)
		}
	} else {
		// 3. Global Tuning (40%)
		subR := rand.Float64()
		if subR < 0.33 {
			m.mutateRepeats(s)
		} else if subR < 0.66 {
			m.mutateFooling(s)
		} else {
			m.mutateTTL(s)
		}
	}

	m.sanitize(s)
}

// sanitize enforces the CFG constraints.
func (m *Mutator) sanitize(s *nfqws.Strategy) {
	isFake := s.Mode == "fake"
	isSplit := s.Mode == "multisplit" || s.Mode == "fakedsplit" || s.Mode == "multidisorder" || s.Mode == "ipfrag1"

	if !isFake {
		s.Fake = nfqws.FakeOptions{}
	}

	if !isSplit {
		s.Split = nfqws.SplitOptions{}
	}

	// Self-repair: Ensure minimal valid configuration
	if isFake && s.Fake.TLS == "" && s.Fake.Quic == "" && len(m.AvailableBins) > 0 {
		m.mutateFake(s)
	}
}

func (m *Mutator) mutateMode(s *nfqws.Strategy) {
	modes := []string{"fake", "multisplit", "multidisorder", "fakedsplit", "ipfrag1"}
	s.Mode = modes[rand.Intn(len(modes))]
}

func (m *Mutator) mutateRepeats(s *nfqws.Strategy) {
	delta := rand.Intn(3) - 1
	s.Repeats += delta
	if s.Repeats < 1 {
		s.Repeats = 1
	}
	if s.Repeats > 20 {
		s.Repeats = 20
	}
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if len(m.AvailableBins) == 0 {
		return
	}
	bin := m.AvailableBins[rand.Intn(len(m.AvailableBins))]

	// Reset fields to avoid conflict
	s.Fake.TLS = ""
	s.Fake.Quic = ""
	s.Fake.TlsMod = ""

	// Content-Aware Assignment
	// Check filename heuristics to determine capability
	isTLS := strings.Contains(bin, "tls") || strings.Contains(bin, "clienthello")
	isQUIC := strings.Contains(bin, "quic")

	if isTLS {
		// It's a TLS packet: Use fake-tls and allow TLS modifiers
		s.Fake.TLS = bin
		mods := []string{"", "rnd", "rndsni"}
		s.Fake.TlsMod = mods[rand.Intn(len(mods))]
	} else if isQUIC {
		// It's a QUIC packet: Use fake-quic and allow generic modifiers
		// Note: rndsni might fail on QUIC if nfqws can't parse it, safer to use 'rnd' or empty
		s.Fake.Quic = bin
		mods := []string{"", "rnd"}
		s.Fake.TlsMod = mods[rand.Intn(len(mods))]
	} else {
		// Unknown/Raw binary (Wireguard, DHT, etc): No modifiers allowed
		// Randomly assign to TLS or QUIC slot purely as payload carrier
		if rand.Float64() > 0.5 {
			s.Fake.TLS = bin
		} else {
			s.Fake.Quic = bin
		}
		// STRICTLY NO MODS for raw binaries
		s.Fake.TlsMod = ""
	}
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	if rand.Float64() < 0.5 {
		positions := []string{"1", "2", "3", "1,sniext+1", "2,sniext+1", "1,midsld"}
		s.Split.Pos = positions[rand.Intn(len(positions))]
	}

	if rand.Float64() < 0.5 {
		if rand.Intn(2) == 0 {
			s.Split.SeqOvl = 0
			s.Split.Pattern = ""
		} else {
			s.Split.SeqOvl = 1 + rand.Intn(1000)
			if len(m.AvailableBins) > 0 && rand.Float64() > 0.7 {
				s.Split.Pattern = m.AvailableBins[rand.Intn(len(m.AvailableBins))]
			}
		}
	}
}

func (m *Mutator) mutateTTL(s *nfqws.Strategy) {
	if rand.Intn(2) == 0 {
		s.TTL.Fixed = rand.Intn(10) + 1
		s.TTL.Auto = 0
	} else {
		s.TTL.Auto = rand.Intn(5) + 1
		s.TTL.Fixed = 0
	}
}

func (m *Mutator) mutateFooling(s *nfqws.Strategy) {
	if rand.Float64() < 0.3 {
		s.Fooling.Md5Sig = !s.Fooling.Md5Sig
	}
	if rand.Float64() < 0.3 {
		s.Fooling.BadSum = !s.Fooling.BadSum
	}
	if rand.Float64() < 0.3 {
		s.Fooling.BadSeq = !s.Fooling.BadSeq
	}
}
