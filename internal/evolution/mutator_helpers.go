package evolution

import (
	"strings"

	"prikop/internal/nfqws2"
)

// ---- helpers -----------------------------------------------------------------

// funcPhase returns the canonical phase bucket of a known desync function.
// Lower phases render first: synack/window setup, then fakes, then tamper, then
// the split/segment family.
func funcPhase(fn string) int {
	switch fn {
	case "synack_split", "synack", "wsize", "wssize", "syndata":
		return 0
	case "fake", "rst":
		return 1
	case "http_hostcase", "http_domcase", "http_methodeol", "http_unixeol":
		return 2
	default:
		// multisplit, multidisorder, fakedsplit, fakeddisorder, hostfakesplit,
		// tcpseg, udplen, drop, send, pktmod, dht_dn
		return 3
	}
}

func isSplitFunc(fn string) bool {
	switch fn {
	case "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "tcpseg":
		return true
	}
	return false
}

func needsBlob(fn string) bool {
	return fn == "fake" || fn == "syndata"
}

func needsPos(fn string) bool {
	switch fn {
	case "multisplit", "multidisorder", "fakedsplit", "fakeddisorder":
		return true
	}
	return false
}

func simplifyFunc(fn string) string {
	switch fn {
	case "multidisorder":
		return "multisplit"
	case "fakeddisorder":
		return "fakedsplit"
	default:
		return fn
	}
}

// toDisorder converts split-family actions to their disorder variant, or adds a
// multidisorder if none is present.
func (m *Mutator) toDisorder(s *nfqws2.Strategy) {
	converted := false
	for i := range s.Actions {
		switch s.Actions[i].Func {
		case "multisplit":
			s.Actions[i].Func = "multidisorder"
			converted = true
		case "fakedsplit":
			s.Actions[i].Func = "fakeddisorder"
			converted = true
		}
	}
	if !converted {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "multidisorder"})
	}
}

// primaryIdx returns the index of the action fooling/TTL/repeats attach to:
// prefer a split-family action, then a fake, then the first action.
func (m *Mutator) primaryIdx(s *nfqws2.Strategy) int {
	if i := m.splitIdx(s); i >= 0 {
		return i
	}
	if i := findFunc(s, "fake"); i >= 0 {
		return i
	}
	if len(s.Actions) > 0 {
		return 0
	}
	return -1
}

// splitIdx returns the index of the first split-family action, or -1.
func (m *Mutator) splitIdx(s *nfqws2.Strategy) int {
	for i := range s.Actions {
		if isSplitFunc(s.Actions[i].Func) {
			return i
		}
	}
	return -1
}

func findFunc(s *nfqws2.Strategy, fn string) int {
	for i := range s.Actions {
		if s.Actions[i].Func == fn {
			return i
		}
	}
	return -1
}

func (m *Mutator) pickBlob() string {
	if m.Proto == "udp" {
		return quicBlobs[rng.IntN(len(quicBlobs))]
	}
	return tlsBlobs[rng.IntN(len(tlsBlobs))]
}

func (m *Mutator) defaultBlob() string {
	if m.Proto == "udp" {
		return nfqws2.BlobDefaultQUIC
	}
	return nfqws2.BlobDefaultTLS
}

// protoBlob keeps the default blob consistent with the profile transport.
// Custom 0xHEX blobs are left untouched.
func (m *Mutator) protoBlob(blob string) string {
	if m.Proto == "udp" && blob == nfqws2.BlobDefaultTLS {
		return nfqws2.BlobDefaultQUIC
	}
	if m.Proto == "tcp" && blob == nfqws2.BlobDefaultQUIC {
		return nfqws2.BlobDefaultTLS
	}
	return blob
}

func (m *Mutator) defaultAction() nfqws2.Action {
	return nfqws2.Action{
		Func:   "fake",
		Params: []nfqws2.Param{nfqws2.P("blob", m.defaultBlob())},
	}
}

func (m *Mutator) ensureFilter(s *nfqws2.Strategy) {
	if s.Filter.TCP != "" || s.Filter.UDP != "" {
		return
	}
	if m.Proto == "udp" {
		s.Filter = nfqws2.Filter{UDP: "443", L7: []string{"quic"}, Payload: []string{"quic_initial"}}
	} else {
		s.Filter = nfqws2.Filter{TCP: "80,443", L7: []string{"tls", "http"}, Payload: []string{"tls_client_hello"}}
	}
}

func setWsize(a *nfqws2.Action) {
	p := wsizePairs[rng.IntN(len(wsizePairs))]
	a.SetParam("wsize", p[0])
	if p[1] != "" {
		a.SetParam("scale", p[1])
	} else {
		a.DelParam("scale")
	}
}

func hasBadSeq(a *nfqws2.Action) bool {
	if _, ok := a.Param("tcp_seq"); ok {
		return true
	}
	_, ok := a.Param("tcp_ack")
	return ok
}

// setBadSeq maps v1 badseq onto v2: tcp_seq for SYN-time actions, tcp_ack (+
// tcp_ts_up, the Linux badack workaround) for data actions.
func setBadSeq(a *nfqws2.Action) {
	if a.Func == "syndata" || a.Func == "synack_split" || a.Func == "synack" {
		a.SetParam("tcp_seq", BadSeqValue)
		return
	}
	a.SetParam("tcp_ack", BadAckValue)
	a.SetParam("tcp_ts_up", "")
}

func clearBadSeq(a *nfqws2.Action) {
	a.DelParam("tcp_seq")
	a.DelParam("tcp_ack")
	a.DelParam("tcp_ts_up")
}

func dedupeActions(as []nfqws2.Action) []nfqws2.Action {
	seen := make(map[string]struct{}, len(as))
	out := as[:0:0]
	for _, a := range as {
		key := actionKey(a)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

func actionKey(a nfqws2.Action) string {
	var b strings.Builder
	b.WriteString(a.Func)
	for _, p := range a.Params {
		b.WriteByte('|')
		b.WriteString(p.Key)
		b.WriteByte('=')
		b.WriteString(p.Value)
	}
	return b.String()
}
