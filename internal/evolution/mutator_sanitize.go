package evolution

import (
	"sort"
	"strconv"

	"prikop/internal/nfqws2"
)

// ---- sanitize ----------------------------------------------------------------

// sanitize canonicalises a strategy into a valid, phase-ordered genome:
//   - drop actions whose func is outside KnownFuncs (covers IPv6-only pseudo-funcs)
//   - strip IPv6-only extension-header foolings (and TCP foolings on UDP)
//   - reorder actions into canonical phases (synack | fake/rst | split family)
//   - ensure fake/syndata actions carry a blob, split actions carry a pos
//   - clamp repeats into [MinRepeats, MaxRepeatsOverall]
//   - normalise blobs to the profile proto (TLS on TCP, QUIC on UDP)
//   - dedupe identical actions and guarantee a non-empty strategy + filter
//
// The result always passes nfqws2.Strategy.Valid().
func (m *Mutator) sanitize(s *nfqws2.Strategy) {
	// 1. drop unknown/IPv6-only funcs; strip incompatible params.
	kept := s.Actions[:0:0]
	for _, a := range s.Actions {
		if _, ok := nfqws2.KnownFuncs[a.Func]; !ok {
			continue
		}
		for _, k := range ipv6OnlyParams {
			a.DelParam(k)
		}
		if m.Proto == "udp" {
			for _, k := range tcpOnlyParams {
				a.DelParam(k)
			}
		}
		kept = append(kept, a)
	}
	s.Actions = kept

	// 2. stable phase reorder.
	sort.SliceStable(s.Actions, func(i, j int) bool {
		return funcPhase(s.Actions[i].Func) < funcPhase(s.Actions[j].Func)
	})

	// 3. per-action fixups.
	for i := range s.Actions {
		a := &s.Actions[i]

		if v, ok := a.Param("blob"); ok && v != "" {
			a.SetParam("blob", m.protoBlob(v))
		}
		if needsBlob(a.Func) {
			if v, ok := a.Param("blob"); !ok || v == "" {
				a.SetParam("blob", m.defaultBlob())
			}
		}

		switch {
		case a.Func == "tcpseg":
			if _, ok := a.Param("pos"); !ok {
				a.SetParam("pos", "1,midsld")
			}
		case needsPos(a.Func):
			if _, ok := a.Param("pos"); !ok {
				a.SetParam("pos", "2")
			}
		}

		if v, ok := a.Param("repeats"); ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < MinRepeats {
				n = MinRepeats
			}
			if n > MaxRepeatsOverall {
				n = MaxRepeatsOverall
			}
			if n == 1 {
				a.DelParam("repeats")
			} else {
				a.SetParam("repeats", strconv.Itoa(n))
			}
		}
	}

	// 4. dedupe identical actions (keep first occurrence).
	s.Actions = dedupeActions(s.Actions)

	// 5. never leave an empty genome.
	if len(s.Actions) == 0 {
		s.Actions = []nfqws2.Action{m.defaultAction()}
	}

	// 6. guarantee a filter matching the proto.
	m.ensureFilter(s)
}
