package evolution

import (
	"strings"
	"testing"

	"prikop/internal/nfqws"
)

// Each case is crafted to avoid sanitize's random branches (it only calls
// mutateFake when every fake payload is empty, and only randomizes HostMod for
// hostfakesplit modes), so the assertions are deterministic.

func newTestMutator(proto string) *Mutator {
	return NewMutator([]string{"/app/fake/x.bin"}, proto)
}

func TestSanitizeCanonicalizesModeOrder(t *testing.T) {
	s := &nfqws.Strategy{
		Mode: "multisplit,fake,synack",
		Fake: nfqws.FakeOptions{TLS: "/app/fake/x.bin"},
	}
	newTestMutator("tcp").sanitize(s)

	// phase order: p0 (synack) -> p1 (fake) -> p2 (multisplit)
	if s.Mode != "synack,fake,multisplit" {
		t.Fatalf("Mode = %q, want %q", s.Mode, "synack,fake,multisplit")
	}
}

func TestSanitizeStripsIPv6Modes(t *testing.T) {
	s := &nfqws.Strategy{
		Mode: "fake,ipfrag1,hopbyhop,destopt,multisplit",
		Fake: nfqws.FakeOptions{TLS: "/app/fake/x.bin"},
	}
	newTestMutator("tcp").sanitize(s)

	for _, banned := range []string{"ipfrag1", "hopbyhop", "destopt"} {
		if strings.Contains(s.Mode, banned) {
			t.Fatalf("Mode %q still contains IPv6-only mode %q", s.Mode, banned)
		}
	}
	if s.Mode != "fake,multisplit" {
		t.Fatalf("Mode = %q, want %q", s.Mode, "fake,multisplit")
	}
}

func TestSanitizeClearsFakeWhenNoFakeMode(t *testing.T) {
	s := &nfqws.Strategy{
		Mode: "multisplit",
		Fake: nfqws.FakeOptions{TLS: "/app/fake/x.bin", Quic: "/app/fake/q.bin"},
	}
	newTestMutator("tcp").sanitize(s)

	if s.Fake != (nfqws.FakeOptions{}) {
		t.Fatalf("Fake = %+v, want zero value", s.Fake)
	}
}

func TestSanitizeProtoPrunesFakePayloads(t *testing.T) {
	t.Run("udp clears tls fake", func(t *testing.T) {
		s := &nfqws.Strategy{
			Mode: "fake",
			Fake: nfqws.FakeOptions{TLS: "/app/fake/t.bin", Quic: "/app/fake/q.bin"},
		}
		newTestMutator("udp").sanitize(s)
		if s.Fake.TLS != "" {
			t.Fatalf("udp: TLS = %q, want empty", s.Fake.TLS)
		}
		if s.Fake.Quic != "/app/fake/q.bin" {
			t.Fatalf("udp: Quic = %q, want kept", s.Fake.Quic)
		}
	})

	t.Run("tcp clears udp fakes", func(t *testing.T) {
		s := &nfqws.Strategy{
			Mode: "fake",
			Fake: nfqws.FakeOptions{TLS: "/app/fake/t.bin", Quic: "/app/fake/q.bin", UnknownUdp: "/app/fake/u.bin"},
		}
		newTestMutator("tcp").sanitize(s)
		if s.Fake.TLS != "/app/fake/t.bin" {
			t.Fatalf("tcp: TLS = %q, want kept", s.Fake.TLS)
		}
		if s.Fake.Quic != "" || s.Fake.UnknownUdp != "" {
			t.Fatalf("tcp: Quic=%q UnknownUdp=%q, want empty", s.Fake.Quic, s.Fake.UnknownUdp)
		}
	})
}

func TestSanitizeClampsRepeats(t *testing.T) {
	tooHigh := &nfqws.Strategy{Mode: "fake", Fake: nfqws.FakeOptions{TLS: "/app/fake/x.bin"}, Repeats: 99}
	newTestMutator("tcp").sanitize(tooHigh)
	if tooHigh.Repeats != MaxRepeatsOverall {
		t.Fatalf("Repeats = %d, want clamp to %d", tooHigh.Repeats, MaxRepeatsOverall)
	}

	tooLow := &nfqws.Strategy{Mode: "fake", Fake: nfqws.FakeOptions{TLS: "/app/fake/x.bin"}, Repeats: 0}
	newTestMutator("tcp").sanitize(tooLow)
	if tooLow.Repeats != MinRepeats {
		t.Fatalf("Repeats = %d, want clamp to %d", tooLow.Repeats, MinRepeats)
	}
}

func TestSanitizeDropsIncompatibleOptions(t *testing.T) {
	s := &nfqws.Strategy{
		Mode:    "fake",
		Fake:    nfqws.FakeOptions{TLS: "/app/fake/x.bin"},
		Fooling: nfqws.FoolingSet{HopByHop: true, HopByHop2: true},
		Split:   nfqws.SplitOptions{Pos: "5", SeqOvl: 10},
		Tamper:  nfqws.TamperOptions{HostCase: true},
	}
	newTestMutator("tcp").sanitize(s)

	if s.Fooling.HopByHop || s.Fooling.HopByHop2 {
		t.Fatalf("HopByHop flags must be cleared, got %+v", s.Fooling)
	}
	if s.Split != (nfqws.SplitOptions{}) {
		t.Fatalf("Split must be cleared when mode has no split: %+v", s.Split)
	}
	if s.Tamper != (nfqws.TamperOptions{}) {
		t.Fatalf("Tamper must be cleared when mode has no tamper: %+v", s.Tamper)
	}
}
