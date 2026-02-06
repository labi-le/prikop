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

func (m *Mutator) Mutate(s *nfqws.Strategy) {
	// Вероятности мутаций
	r := rand.Float64()

	if r < 0.25 {
		m.mutateMode(s)
	} else if r < 0.45 {
		m.mutateRepeats(s)
	} else if r < 0.65 {
		m.mutateFake(s)
	} else if r < 0.80 {
		m.mutateSplit(s)
	} else if r < 0.90 {
		m.mutateFooling(s)
	} else {
		m.mutateTTL(s)
	}

	// Шанс двойной мутации
	if rand.Float64() < 0.2 {
		m.mutateRepeats(s)
	}
}

func (m *Mutator) mutateMode(s *nfqws.Strategy) {
	modes := []string{"fake", "multisplit", "multidisorder", "fakedsplit", "ipfrag1"}
	s.Mode = modes[rand.Intn(len(modes))]
	// Сброс несовместимых параметров при смене режима — это слишком сложно,
	// nfqws сам проигнорирует лишние флаги, так что оставляем как есть.
}

func (m *Mutator) mutateRepeats(s *nfqws.Strategy) {
	delta := rand.Intn(3) - 1
	s.Repeats += delta
	if s.Repeats < 1 {
		s.Repeats = 1
	}
	if s.Repeats > 15 {
		s.Repeats = 15
	}
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if len(m.AvailableBins) == 0 {
		return
	}
	bin := m.AvailableBins[rand.Intn(len(m.AvailableBins))]

	if rand.Float64() > 0.5 {
		s.Fake.TLS = bin
		s.Fake.Quic = ""
	} else {
		s.Fake.Quic = bin
		s.Fake.TLS = ""
	}

	mods := []string{"none", "rnd", "rndsni"}
	s.Fake.Mod = mods[rand.Intn(len(mods))]
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	positions := []string{"1", "2", "3", "1,sniext+1", "2,sniext+1", "1,midsld"}
	s.Split.Pos = positions[rand.Intn(len(positions))]

	if rand.Intn(2) == 0 {
		s.Split.SeqOvl = 0
		s.Split.Pattern = ""
	} else {
		s.Split.SeqOvl = 1 + rand.Intn(1000)
		if len(m.AvailableBins) > 0 && rand.Float64() > 0.6 {
			s.Split.Pattern = m.AvailableBins[rand.Intn(len(m.AvailableBins))]
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
	s.Fooling.Md5Sig = !s.Fooling.Md5Sig
	if rand.Intn(2) == 0 {
		s.Fooling.BadSum = !s.Fooling.BadSum
	}
	if rand.Intn(2) == 0 {
		s.Fooling.BadSeq = !s.Fooling.BadSeq
	}
}
