package evolution

import (
	"math/rand"
	"prikop/internal/model"
	"strings"

	"prikop/internal/nfqws"
)

type Mutator struct {
	AvailableBins []string
	Proto         string
}

func NewMutator(bins []string, proto string) *Mutator {
	return &Mutator{AvailableBins: bins, Proto: proto}
}

func (m *Mutator) Mutate(s *nfqws.Strategy) {
	m.SmartMutate(s, model.ReasonNone)
}

func (m *Mutator) SmartMutate(s *nfqws.Strategy, feedback model.FailureReason) {
	r := rand.Float64()
	m.sanitize(s)

	if feedback == model.ReasonReset {
		if r < 0.4 {
			m.mutateFooling(s)
		} else if r < 0.7 {
			m.mutateSplit(s)
		} else {
			m.mutateFake(s)
		}
		m.sanitize(s)
		return
	}

	if feedback == model.ReasonTimeout {
		if r < 0.5 {
			m.mutateRepeats(s)
		} else if r < 0.8 {
			m.mutateFake(s)
		} else {
			m.mutateMode(s)
		}
		m.sanitize(s)
		return
	}

	// Random Exploration
	if r < 0.15 {
		m.mutateMode(s)
		if strings.Contains(s.Mode, "fake") {
			m.mutateFake(s)
		}
		if strings.Contains(s.Mode, "split") {
			m.mutateSplit(s)
		}
	} else if r < 0.4 {
		m.mutateFake(s)
	} else if r < 0.6 {
		m.mutateSplit(s)
	} else if r < 0.8 {
		m.mutateFooling(s)
	} else {
		m.mutateGlobal(s)
	}

	m.sanitize(s)
}

func (m *Mutator) sanitize(s *nfqws.Strategy) {
	isFake := strings.Contains(s.Mode, "fake")
	isSplit := strings.Contains(s.Mode, "split") || strings.Contains(s.Mode, "disorder") || strings.Contains(s.Mode, "ipfrag")
	isHostFake := strings.Contains(s.Mode, "hostfakesplit")
	isFakedSplit := strings.Contains(s.Mode, "fakedsplit") || strings.Contains(s.Mode, "fakeddisorder")

	if !isFake {
		s.Fake = nfqws.FakeOptions{}
	} else {
		if s.Fake.TLS == "" && s.Fake.Quic == "" && s.Fake.UnknownUdp == "" && len(m.AvailableBins) > 0 {
			m.mutateFake(s)
		}

		// Protocol Enforce
		if m.Proto == "udp" {
			s.Fake.TLS = ""
		} else {
			s.Fake.Quic = ""
			s.Fake.UnknownUdp = ""
		}
	}

	// General Split Cleanup
	if !isSplit && !isHostFake {
		s.Split = nfqws.SplitOptions{}
	}

	// Strict cleanup for mode-specific params
	if !isHostFake {
		s.Split.HostMod = ""
		s.Split.HostMid = ""
	} else if s.Split.HostMod == "" {
		s.Split.HostMod = "host=www.google.com"
	}

	if !isFakedSplit {
		s.Split.FakedMod = ""
		s.Split.FakedPattern = ""
	}

	if s.Repeats < 1 {
		s.Repeats = 1
	} else if s.Repeats > 10 {
		s.Repeats = 10
	}
}

func (m *Mutator) mutateMode(s *nfqws.Strategy) {
	if m.Proto == "tcp" {
		modes := []string{
			"fake,multisplit", "fake,multisplit", // Combo Priority
			"hostfakesplit", "hostfakesplit", // Masking Priority
			"fake",
			"multisplit",
			"fakedsplit",
		}
		s.Mode = modes[rand.Intn(len(modes))]
	} else {
		modes := []string{
			"fake", "fake", "fake", // UDP loves Fake
			"multisplit",
		}
		s.Mode = modes[rand.Intn(len(modes))]
	}
}

func (m *Mutator) mutateRepeats(s *nfqws.Strategy) {
	delta := rand.Intn(3) - 1
	s.Repeats += delta
	maxRepeats := 6
	if m.Proto == "udp" {
		maxRepeats = 10 // Higher for UDP
	}
	if s.Repeats > maxRepeats {
		s.Repeats = maxRepeats
	}
	if rand.Float64() < 0.1 {
		s.Repeats = 1 + rand.Intn(maxRepeats)
	}
}

func (m *Mutator) mutateWSS(s *nfqws.Strategy) {
	if rand.Float64() < 0.3 {
		s.WSS.Enabled = !s.WSS.Enabled
	}
	if s.WSS.Enabled {
		sizes := []string{"1:6", "1:8", "1:10", "1:100", "500", "800"}
		s.WSS.Value = sizes[rand.Intn(len(sizes))]
	}
}

func (m *Mutator) mutateGlobal(s *nfqws.Strategy) {
	r := rand.Float64()
	if r < 0.3 {
		m.mutateRepeats(s)
	} else if r < 0.5 {
		// Toggle AnyProtocol/Cutoff for UDP
		if m.Proto == "udp" {
			s.AnyProtocol = !s.AnyProtocol
			if s.AnyProtocol {
				s.Cutoff = "d2"
			} else {
				s.Cutoff = ""
			}
		}
	} else {
		m.mutateWSS(s)
	}
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if len(m.AvailableBins) == 0 {
		return
	}
	bin := m.AvailableBins[rand.Intn(len(m.AvailableBins))]

	if m.Proto == "tcp" {
		s.Fake.TLS = bin
		r := rand.Float64()
		if r < 0.3 {
			s.Fake.TlsMod = "rndsni"
		} else if r < 0.7 {
			s.Fake.TlsMod = "rnd,dupsid" // Advanced mod
		} else {
			s.Fake.TlsMod = "rnd"
		}
	} else {
		// UDP Logic
		r := rand.Float64()
		if r < 0.5 {
			s.Fake.Quic = bin
			s.Fake.TlsMod = "rnd"
			s.Fake.UnknownUdp = ""
		} else {
			s.Fake.UnknownUdp = bin
			s.Fake.Quic = ""
		}
	}
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	if strings.Contains(s.Mode, "hostfakesplit") {
		// Mutate Host
		hosts := []string{
			"host=www.google.com",
			"host=mapgl.2gis.com",
			"host=api.google.com",
			"host=cloudflare.com",
		}
		s.Split.HostMod = hosts[rand.Intn(len(hosts))]
		s.Split.SeqOvl = 0
		return
	}

	positions := []string{"1", "2", "2,sld", "2,sniext+1"}
	s.Split.Pos = positions[rand.Intn(len(positions))]

	if rand.Float64() < 0.6 {
		// User config used 620, let's allow large overlaps
		s.Split.SeqOvl = 1 + rand.Intn(700)
	} else {
		s.Split.SeqOvl = 0
	}

	if rand.Float64() < 0.4 && len(m.AvailableBins) > 0 {
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
		if rand.Float64() < 0.25 {
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
