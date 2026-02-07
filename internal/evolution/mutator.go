package evolution

import (
	"math/rand"

	"prikop/internal/nfqws"
)

type Mutator struct {
	AvailableBins []string
}

func NewMutator(bins []string) *Mutator {
	return &Mutator{AvailableBins: bins}
}

// Mutate implements Grammar-Based Fuzzing (Constraint Enforcement).
// Instead of purely stochastic changes, it respects the dependencies between
// the 'Mode' and its associated parameters (Split vs Fake).
func (m *Mutator) Mutate(s *nfqws.Strategy) {
	r := rand.Float64()

	// Hierarchical Mutation Strategy
	// 1. Structure Mutation (20%): Change the fundamental approach (Mode)
	if r < 0.20 {
		m.mutateMode(s)
		m.sanitize(s) // Enforce grammar immediately after structure change
		return
	}

	// 2. Parameter Tuning (40%): Mutate parameters relevant to the current Mode
	if r < 0.60 {
		if s.Mode == "fake" {
			m.mutateFake(s)
		} else {
			// multisplit, multidisorder, fakedsplit, ipfrag1
			m.mutateSplit(s)
		}
	} else {
		// 3. Global Tuning (40%): Mutate universal parameters (Repeats, TTL, Fooling)
		subR := rand.Float64()
		if subR < 0.33 {
			m.mutateRepeats(s)
		} else if subR < 0.66 {
			m.mutateFooling(s)
		} else {
			m.mutateTTL(s)
		}
	}

	// Final safeguard to ensure no junk DNA persists
	m.sanitize(s)
}

// sanitize enforces the CFG constraints: clears fields incompatible with the current Mode.
func (m *Mutator) sanitize(s *nfqws.Strategy) {
	isFake := s.Mode == "fake"
	// Modes that utilize split logic (pos, seqovl, pattern)
	isSplit := s.Mode == "multisplit" || s.Mode == "fakedsplit" || s.Mode == "multidisorder" || s.Mode == "ipfrag1"

	if !isFake {
		s.Fake = nfqws.FakeOptions{} // Reset Fake options if not in fake mode
	}

	if !isSplit {
		s.Split = nfqws.SplitOptions{} // Reset Split options if not in split mode
	}

	// Self-repair: Ensure minimal valid configuration
	if isFake && s.Fake.TLS == "" && s.Fake.Quic == "" && len(m.AvailableBins) > 0 {
		// If we switched to fake but have no payload, inject one
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
	if s.Repeats > 20 { // Cap repeats to prevent timeouts
		s.Repeats = 20
	}
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if len(m.AvailableBins) == 0 {
		return
	}
	bin := m.AvailableBins[rand.Intn(len(m.AvailableBins))]

	// Toggle between TLS and QUIC payloads
	if rand.Float64() > 0.5 {
		s.Fake.TLS = bin
		s.Fake.Quic = ""
	} else {
		s.Fake.Quic = bin
		s.Fake.TLS = ""
	}

	mods := []string{"", "rnd", "rndsni"}
	s.Fake.TlsMod = mods[rand.Intn(len(mods))]
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	// Mutate Position
	if rand.Float64() < 0.5 {
		positions := []string{"1", "2", "3", "1,sniext+1", "2,sniext+1", "1,midsld"}
		s.Split.Pos = positions[rand.Intn(len(positions))]
	}

	// Mutate SeqOvl (only relevant for splitting)
	if rand.Float64() < 0.5 {
		if rand.Intn(2) == 0 {
			s.Split.SeqOvl = 0
			s.Split.Pattern = ""
		} else {
			s.Split.SeqOvl = 1 + rand.Intn(1000)
			// Pattern injection constraint: only if we have bins
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
	// Independent mutations for boolean flags
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
