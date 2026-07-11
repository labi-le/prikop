package evolution

import (
	"testing"

	"prikop/internal/model"
	"prikop/internal/nfqws2"
)

// sanitize is deterministic (no randomness), so these assertions are stable.

func newTestMutator(proto string) *Mutator {
	return NewMutator([]string{"/app/fake/x.bin"}, proto)
}

func TestSanitizeCanonicalizesPhaseOrder(t *testing.T) {
	// Actions given out of order: split (phase 3), synack_split (phase 0), fake (phase 1).
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "443", L7: []string{"tls"}, Payload: []string{"tls_client_hello"}},
		Actions: []nfqws2.Action{
			{Func: "multisplit", Params: []nfqws2.Param{nfqws2.P("pos", "1,midsld")}},
			{Func: "synack_split"},
			{Func: "fake", Params: []nfqws2.Param{nfqws2.P("blob", nfqws2.BlobDefaultTLS)}},
		},
	}
	newTestMutator("tcp").sanitize(s)

	if got := s.Signature(); got != "synack_split,fake,multisplit" {
		t.Fatalf("Signature() = %q, want %q", got, "synack_split,fake,multisplit")
	}
	if err := s.Valid(); err != nil {
		t.Fatalf("Valid() = %v, want nil", err)
	}
}

func TestSanitizeDropsUnknownAndIPv6Funcs(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "443", L7: []string{"tls"}, Payload: []string{"tls_client_hello"}},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{nfqws2.P("blob", nfqws2.BlobDefaultTLS)}},
			{Func: "hopbyhop"}, // IPv6-only pseudo-func -> dropped
			{Func: "destopt"},  // IPv6-only pseudo-func -> dropped
			{Func: "ipfrag1"},  // IPv6-only pseudo-func -> dropped
			{Func: "multisplit", Params: []nfqws2.Param{nfqws2.P("pos", "1")}},
		},
	}
	newTestMutator("tcp").sanitize(s)

	for _, banned := range []string{"hopbyhop", "destopt", "ipfrag1"} {
		if s.HasFunc(banned) {
			t.Fatalf("banned func %q survived sanitize: %s", banned, s.String())
		}
	}
	if got := s.Signature(); got != "fake,multisplit" {
		t.Fatalf("Signature() = %q, want %q", got, "fake,multisplit")
	}
	if err := s.Valid(); err != nil {
		t.Fatalf("Valid() = %v, want nil", err)
	}
}

func TestSanitizeStripsIPv6OnlyFoolingParams(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "443"},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{
				nfqws2.P("blob", nfqws2.BlobDefaultTLS),
				nfqws2.Flag("ip6_hopbyhop"),
				nfqws2.Flag("ip6_destopt"),
				nfqws2.Flag("tcp_md5"),
			}},
		},
	}
	newTestMutator("tcp").sanitize(s)

	if s.HasParam("ip6_hopbyhop") || s.HasParam("ip6_destopt") {
		t.Fatalf("IPv6-only fooling params survived: %s", s.String())
	}
	if !s.HasParam("tcp_md5") {
		t.Fatalf("tcp_md5 was wrongly stripped on TCP: %s", s.String())
	}
}

func TestSanitizeClampsRepeats(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "443"},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{
				nfqws2.P("blob", nfqws2.BlobDefaultTLS),
				nfqws2.P("repeats", "99"),
			}},
		},
	}
	newTestMutator("tcp").sanitize(s)

	v, ok := s.Actions[0].Param("repeats")
	if !ok {
		t.Fatalf("repeats param dropped, want clamped to %d", MaxRepeatsOverall)
	}
	if v != "10" {
		t.Fatalf("repeats = %q, want %q", v, "10")
	}
}

func TestSanitizeDropsUnitRepeats(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "443"},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{
				nfqws2.P("blob", nfqws2.BlobDefaultTLS),
				nfqws2.P("repeats", "0"), // below MinRepeats -> normalised to 1 -> dropped
			}},
		},
	}
	newTestMutator("tcp").sanitize(s)

	if _, ok := s.Actions[0].Param("repeats"); ok {
		t.Fatalf("repeats=1 should be dropped as the default: %s", s.String())
	}
}

func TestSanitizeEnsuresFakeBlob(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter:  nfqws2.Filter{TCP: "443"},
		Actions: []nfqws2.Action{{Func: "fake"}}, // no blob
	}
	newTestMutator("tcp").sanitize(s)

	v, ok := s.Actions[0].Param("blob")
	if !ok || v != nfqws2.BlobDefaultTLS {
		t.Fatalf("fake blob = %q (present=%v), want %q", v, ok, nfqws2.BlobDefaultTLS)
	}
}

func TestSanitizeNormalisesBlobToProto(t *testing.T) {
	// A TLS blob under a UDP profile must be rewritten to the QUIC default.
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{UDP: "443", L7: []string{"quic"}},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{nfqws2.P("blob", nfqws2.BlobDefaultTLS)}},
		},
	}
	newTestMutator("udp").sanitize(s)

	v, _ := s.Actions[0].Param("blob")
	if v != nfqws2.BlobDefaultQUIC {
		t.Fatalf("udp fake blob = %q, want %q", v, nfqws2.BlobDefaultQUIC)
	}
}

func TestSanitizeStripsTCPFoolingOnUDP(t *testing.T) {
	s := &nfqws2.Strategy{
		Filter: nfqws2.Filter{UDP: "443", L7: []string{"quic"}},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{
				nfqws2.P("blob", nfqws2.BlobDefaultQUIC),
				nfqws2.Flag("tcp_md5"),
				nfqws2.P("tcp_ack", "-66000"),
			}},
		},
	}
	newTestMutator("udp").sanitize(s)

	if s.HasParam("tcp_md5") || s.HasBadSeq() {
		t.Fatalf("TCP fooling survived on UDP profile: %s", s.String())
	}
}

func TestSanitizeGuaranteesNonEmpty(t *testing.T) {
	s := &nfqws2.Strategy{Actions: []nfqws2.Action{{Func: "unknown_bogus_func"}}}
	newTestMutator("tcp").sanitize(s)

	if err := s.Valid(); err != nil {
		t.Fatalf("empty-after-prune strategy not repaired: Valid() = %v", err)
	}
}

// TestMutateInvariants asserts the invariants that hold for EVERY random branch:
// a mutated strategy is always valid and always phase-canonical. It is not
// seeded — the assertions are branch-independent by design.
func TestMutateInvariants(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		m := newTestMutator(proto)
		base := seedStrategy(proto)

		for iter := range 2000 {
			s := base.Clone()
			m.Mutate(&s)

			if err := s.Valid(); err != nil {
				t.Fatalf("[%s iter %d] Valid() = %v for %s", proto, iter, err, s.String())
			}
			if !isPhaseCanonical(&s) {
				t.Fatalf("[%s iter %d] non-canonical phase order: %s", proto, iter, s.Signature())
			}
			if hasOversizedRepeats(&s) {
				t.Fatalf("[%s iter %d] repeats out of range: %s", proto, iter, s.String())
			}
		}
	}
}

func TestSmartMutateInvariantsAllFeedback(t *testing.T) {
	feedbacks := []string{
		"", "reset", "timeout", "skip", "throttle",
		"tls_not_tls", "tls_oversized", "tls_record_overflow", "tls_unrecognized_name",
		"tls_handshake", "tls_internal",
		"tls_alpn", "tls_version", "tls_cipher_suite", "tls_downgrade",
		"tls_bad_signature", "tls_illegal_param", "tls_session_id",
		"tls_bad_mac", "tls_decrypt", "tls_decode", "tls_alert_unexpected",
	}
	m := newTestMutator("tcp")
	base := seedStrategy("tcp")

	for _, fb := range feedbacks {
		for iter := range 500 {
			s := base.Clone()
			m.SmartMutate(&s, model.FailureReason(fb))
			if err := s.Valid(); err != nil {
				t.Fatalf("[fb=%q iter %d] Valid() = %v for %s", fb, iter, err, s.String())
			}
			if !isPhaseCanonical(&s) {
				t.Fatalf("[fb=%q iter %d] non-canonical: %s", fb, iter, s.Signature())
			}
		}
	}
}

// ---- test helpers ------------------------------------------------------------

func seedStrategy(proto string) nfqws2.Strategy {
	if proto == "udp" {
		return nfqws2.Strategy{
			Filter: nfqws2.Filter{UDP: "443", L7: []string{"quic"}, Payload: []string{"quic_initial"}},
			Actions: []nfqws2.Action{
				{Func: "fake", Params: []nfqws2.Param{nfqws2.P("blob", nfqws2.BlobDefaultQUIC)}},
			},
		}
	}
	return nfqws2.Strategy{
		Filter: nfqws2.Filter{TCP: "80,443", L7: []string{"tls", "http"}, Payload: []string{"tls_client_hello"}},
		Actions: []nfqws2.Action{
			{Func: "fake", Params: []nfqws2.Param{nfqws2.P("blob", nfqws2.BlobDefaultTLS)}},
			{Func: "multisplit", Params: []nfqws2.Param{nfqws2.P("pos", "1,midsld")}},
		},
	}
}

func isPhaseCanonical(s *nfqws2.Strategy) bool {
	prev := -1
	for _, a := range s.Actions {
		p := funcPhase(a.Func)
		if p < prev {
			return false
		}
		prev = p
	}
	return true
}

func hasOversizedRepeats(s *nfqws2.Strategy) bool {
	for _, a := range s.Actions {
		v, ok := a.Param("repeats")
		if !ok {
			continue
		}
		n := 0
		for _, c := range v {
			if c < '0' || c > '9' {
				return true
			}
			n = n*10 + int(c-'0')
		}
		if n < MinRepeats || n > MaxRepeatsOverall {
			return true
		}
	}
	return false
}

// The feedback strings above equal the underlying values of model's
// FailureReason constants, so a direct conversion is exact and avoids importing
// every named constant into the test.
