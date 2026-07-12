package evolution

import (
	"fmt"
	"strconv"

	"prikop/internal/nfqws2"
)

// ---- operators ---------------------------------------------------------------

// mutateSimplify reduces aggressiveness when the strategy corrupts the stream.
func (m *Mutator) mutateSimplify(s *nfqws2.Strategy) {
	for i := range s.Actions {
		a := &s.Actions[i]
		// 1. drop NAT-fragile / corrupting foolings
		a.DelParam("badsum")
		a.DelParam("tcp_seq")
		a.DelParam("tcp_ack")
		a.DelParam("tcp_ts_up")
		// 2. drop overlap (SeqOvl damages payload)
		a.DelParam("seqovl")
		a.DelParam("seqovl_pattern")
		// 3. drop fake modifiers
		a.DelParam("tls_mod")
		// 4. reset repeats to the minimum
		a.DelParam("repeats")
		// 5. disorder -> split (disorder often breaks TLS 1.3 state)
		a.Func = simplifyFunc(a.Func)
	}
}

func (m *Mutator) mutateSplit(s *nfqws2.Strategy) {
	idx := m.splitIdx(s)
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "multisplit"})
		idx = len(s.Actions) - 1
	}
	a := &s.Actions[idx]

	if a.Func == "hostfakesplit" {
		a.SetParam("host", CommonHosts[rng.IntN(len(CommonHosts))])
		a.DelParam("seqovl")
		return
	}

	a.SetParam("pos", m.genSplitPos(a.Func))

	if rng.Float64() < ProbSplitSeqOvl {
		a.SetParam("seqovl", strconv.Itoa(magicSeqOvls[rng.IntN(len(magicSeqOvls))]))
	} else {
		a.SetParam("seqovl", strconv.Itoa(1+rng.IntN(5)))
	}
}

// genSplitPos mirrors the v1 marker heuristic, biased toward SNI/host breaks.
func (m *Mutator) genSplitPos(fn string) string {
	markers := []string{
		"midsld", "sniext", "endsld", // high priority (break inside domain/SNI)
		"method", "host", // medium priority
		"2", "3", // low priority (magic numbers)
	}

	gen := func() string {
		marker := markers[rng.IntN(len(markers))]
		if len(marker) < 3 { // bare numeric marker
			return marker
		}
		offset := rng.IntN(5) - 2 // -2..+2
		if offset == 0 {
			return marker
		}
		if offset > 0 {
			return fmt.Sprintf("%s+%d", marker, offset)
		}
		return fmt.Sprintf("%s%d", marker, offset) // negative sign already present
	}

	isMulti := fn == "multisplit" || fn == "multidisorder"
	switch {
	case isMulti && rng.Float64() < ProbSplitMulti:
		return "1," + gen()
	case rng.Float64() < ProbSplitDouble:
		return gen() + "," + gen()
	default:
		return gen()
	}
}

func (m *Mutator) mutateFake(s *nfqws2.Strategy) {
	idx := findFunc(s, "fake")
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "fake"})
		idx = len(s.Actions) - 1
	}
	a := &s.Actions[idx]
	a.SetParam("blob", m.pickBlob())

	if m.Proto == "tcp" && rng.Float64() < ProbFakeTLSMod {
		if rng.Float64() < ProbFakeSNI {
			a.SetParam("tls_mod", "sni="+CommonSNIs[rng.IntN(len(CommonSNIs))])
		} else {
			mod := tlsMods[rng.IntN(len(tlsMods))]
			if mod == "" {
				a.DelParam("tls_mod")
			} else {
				a.SetParam("tls_mod", mod)
			}
		}
	} else {
		a.DelParam("tls_mod")
	}
}

// mutateMode switches the primary desync function (fake <-> split family).
func (m *Mutator) mutateMode(s *nfqws2.Strategy) {
	var bases []string
	if m.Proto == "tcp" {
		bases = []string{"fake", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"}
	} else {
		bases = []string{"fake", "multisplit", "udplen"}
	}
	newFunc := bases[rng.IntN(len(bases))]

	idx := m.primaryIdx(s)
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: newFunc})
		return
	}
	// Switch func and clear now-irrelevant params; sanitize re-adds blob/pos.
	s.Actions[idx].Func = newFunc
	s.Actions[idx].Params = nil
}

func (m *Mutator) mutateFooling(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]

	flipFlag := func(key string, prob float64) {
		if rng.Float64() >= prob {
			return
		}
		if _, ok := a.Param(key); ok {
			a.DelParam(key)
		} else {
			a.SetParam(key, "")
		}
	}

	if m.Proto == "tcp" {
		flipFlag("tcp_md5", ProbFoolingFlip)
		// badsum/badseq are NAT-fragile: heavily biased OFF via the score penalty.
		flipFlag("badsum", ProbFoolingRisky)
		if rng.Float64() < ProbFoolingRisky {
			if hasBadSeq(a) {
				clearBadSeq(a)
			} else {
				setBadSeq(a)
			}
		}
		// datanoack -> tcp_flags_unset=ack
		if rng.Float64() < ProbFoolingFlip {
			if _, ok := a.Param("tcp_flags_unset"); ok {
				a.DelParam("tcp_flags_unset")
			} else {
				a.SetParam("tcp_flags_unset", "ack")
			}
		}
	} else {
		flipFlag("badsum", ProbFoolingRisky)
	}
}

// mutateTamper toggles a tamper-style http_* function (TCP/HTTP only).
func (m *Mutator) mutateTamper(s *nfqws2.Strategy) {
	if m.Proto != "tcp" {
		return
	}
	fn := httpTamperFuncs[rng.IntN(len(httpTamperFuncs))]
	if i := findFunc(s, fn); i >= 0 {
		s.Actions = append(s.Actions[:i], s.Actions[i+1:]...)
		return
	}
	a := nfqws2.Action{Func: fn}
	switch fn {
	case "http_hostcase":
		a.SetParam("spell", tamperSpells[rng.IntN(len(tamperSpells))])
	case "http_methodeol":
		if rng.Float64() < 0.5 {
			a.SetParam("method", methodEols[rng.IntN(len(methodEols))])
		}
	}
	s.Actions = append(s.Actions, a)
}

func (m *Mutator) mutateTTL(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]
	a.DelParam("ip_ttl")
	a.DelParam("ip6_ttl")
	a.DelParam("ip_autottl")
	a.DelParam("ip6_autottl")

	r := rng.Float64()
	if r < ProbTTLAuto {
		delta := -(1 + rng.IntN(3)) // -1..-3
		val := fmt.Sprintf("%d,3-20", delta)
		a.SetParam("ip_autottl", val)
		a.SetParam("ip6_autottl", val)
	} else if r < ProbTTLFixed {
		ttl := 1 + rng.IntN(10)
		a.SetParam("ip_ttl", strconv.Itoa(ttl))
	}
	// else: no TTL fooling
}

func (m *Mutator) mutateRepeats(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]

	cur := 1
	if v, ok := a.Param("repeats"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cur = n
		}
	}
	cur += rng.IntN(3) - 1

	maxR := MaxRepeatsTCP
	if m.Proto == "udp" {
		maxR = MaxRepeatsUDP
	}
	if cur > maxR {
		cur = maxR
	}
	if cur < MinRepeats {
		cur = MinRepeats
	}
	if cur == 1 {
		a.DelParam("repeats")
	} else {
		a.SetParam("repeats", strconv.Itoa(cur))
	}
}

// mutateWSS adds/removes/retunes a wssize action (forces server-side split).
func (m *Mutator) mutateWSS(s *nfqws2.Strategy) {
	if i := findFunc(s, "wssize"); i >= 0 {
		if rng.Float64() < ProbWSSDrop {
			s.Actions = append(s.Actions[:i], s.Actions[i+1:]...)
			return
		}
		setWsize(&s.Actions[i])
		return
	}
	a := nfqws2.Action{Func: "wssize"}
	setWsize(&a)
	s.Actions = append(s.Actions, a)
}

func (m *Mutator) mutateGlobal(s *nfqws2.Strategy) {
	r := rng.Float64()
	switch {
	case r < ProbGlobalRepeats:
		m.mutateRepeats(s)
	case r < ProbGlobalWSS:
		m.mutateWSS(s)
	default:
		if m.Proto == "udp" {
			inc := rng.IntN(32) - 16
			if inc == 0 {
				inc = 2
			}
			if i := findFunc(s, "udplen"); i >= 0 {
				s.Actions[i].SetParam("increment", strconv.Itoa(inc))
			} else {
				s.Actions = append(s.Actions, nfqws2.Action{
					Func:   "udplen",
					Params: []nfqws2.Param{nfqws2.P("increment", strconv.Itoa(inc))},
				})
			}
		} else {
			m.mutateRepeats(s)
		}
	}
}
