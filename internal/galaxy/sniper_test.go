package galaxy

import (
	"testing"

	"prikop/internal/model"
	"prikop/internal/nfqws2"
)

// TestGenerateZeroGenerationValid is the load-bearing invariant: every seeded
// strategy, for both protocols and both recon outcomes, must be a structurally
// valid v2 genome (non-empty, all funcs in KnownFuncs) and carry the correct
// profile filter for its protocol.
func TestGenerateZeroGenerationValid(t *testing.T) {
	bins := []string{
		"tls_clienthello_www_google_com.bin",
		"quic_initial_www_google_com.bin",
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, report := range []model.ReconReport{{}, {BadSumWorks: true}} {
			pop := GenerateZeroGeneration(bins, report, proto)
			if len(pop) == 0 {
				t.Fatalf("proto=%s badsum=%v: empty population", proto, report.BadSumWorks)
			}
			wantUDP := proto == "udp"
			for i, s := range pop {
				if err := s.Valid(); err != nil {
					t.Fatalf("proto=%s [%d] invalid: %v -> %s", proto, i, err, s.String())
				}
				if s.IsUDP() != wantUDP {
					t.Fatalf("proto=%s [%d] IsUDP()=%v, want %v -> %s",
						proto, i, s.IsUDP(), wantUDP, s.String())
				}
			}
		}
	}
}

// TestGenerateZeroGenerationBadSum asserts recon feedback is honoured: enabling
// BadSumWorks strictly increases the count of badsum-fooled seeds (the curated
// Yv imports carry badsum intrinsically, so absolute absence is not required),
// and IPv6-only fragmentation is never emitted (out of scope for the IPv4 path).
func TestGenerateZeroGenerationBadSum(t *testing.T) {
	countBadSum := func(pop []nfqws2.Strategy) int {
		n := 0
		for _, s := range pop {
			if s.HasParam("badsum") {
				n++
			}
			if s.HasFunc("ipfrag") || s.HasFunc("hopbyhop") {
				t.Fatalf("IPv6-only fragmentation func leaked: %s", s.String())
			}
		}
		return n
	}

	base := countBadSum(GenerateZeroGeneration(nil, model.ReconReport{}, "tcp"))
	boosted := countBadSum(GenerateZeroGeneration(nil, model.ReconReport{BadSumWorks: true}, "tcp"))
	if boosted <= base {
		t.Fatalf("BadSumWorks did not add badsum variants: base=%d boosted=%d", base, boosted)
	}
}

// TestGenerateZeroGenerationArchetypes confirms the population is diverse: the
// key archetypes and phase orderings the GA relies on are all present.
func TestGenerateZeroGenerationArchetypes(t *testing.T) {
	pop := GenerateZeroGeneration(nil, model.ReconReport{}, "tcp")
	sigs := map[string]bool{}
	for _, s := range pop {
		sigs[s.Signature()] = true
	}
	for _, want := range []string{
		"multisplit",
		"multidisorder",
		"fake,multisplit",
		"fake,multidisorder",
		"fakedsplit",
		"fakeddisorder",
		"fake,hostfakesplit",
		"tcpseg",
	} {
		if !sigs[want] {
			t.Errorf("missing tcp archetype signature %q; have %v", want, keys(sigs))
		}
	}

	udp := GenerateZeroGeneration(nil, model.ReconReport{}, "udp")
	usigs := map[string]bool{}
	for _, s := range udp {
		usigs[s.Signature()] = true
	}
	for _, want := range []string{"fake", "udplen", "fake,udplen"} {
		if !usigs[want] {
			t.Errorf("missing udp archetype signature %q; have %v", want, keys(usigs))
		}
	}
}

// TestGenerateZeroGenerationDeterministic guards against nondeterministic seeds:
// two calls with identical inputs must yield byte-identical populations.
func TestGenerateZeroGenerationDeterministic(t *testing.T) {
	a := GenerateZeroGeneration(nil, model.ReconReport{}, "tcp")
	b := GenerateZeroGeneration(nil, model.ReconReport{}, "tcp")
	if len(a) != len(b) {
		t.Fatalf("nondeterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			t.Fatalf("nondeterministic at %d:\n  %s\n  %s", i, a[i].String(), b[i].String())
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDiscordSeeds confirms the flowseal/Zapret-Manager discord.media techniques
// are seeded into the TCP population, scoped to Discord's TCP ports (443 for the
// gateway/API/CDN plus the 2053-8443 media ports so they also apply to the
// discord_* providers), render to their exact v2 form, and never leak to UDP.
func TestDiscordSeeds(t *testing.T) {
	const discordPorts = "80,443,2053,2083,2087,2096,8443"
	const want652 = "--filter-tcp=80,443,2053,2083,2087,2096,8443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=2:seqovl=652"

	discord := 0
	found652 := false
	for _, s := range GenerateZeroGeneration(nil, model.ReconReport{}, "tcp") {
		if s.Filter.TCP != discordPorts {
			continue
		}
		discord++
		if s.String() == want652 {
			found652 = true
		}
	}
	if discord < 5 {
		t.Fatalf("expected the discord.media seed set (>=5), got %d discord-filtered strategies", discord)
	}
	if !found652 {
		t.Fatalf("multisplit seqovl=652 pos=2 discord seed missing or mis-rendered")
	}

	for _, s := range GenerateZeroGeneration(nil, model.ReconReport{}, "udp") {
		if s.Filter.TCP == discordPorts {
			t.Fatalf("discord TCP seed leaked into the UDP population: %s", s.String())
		}
	}
}
