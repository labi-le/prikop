package orchestrator

import (
	"testing"
)

func TestOptimizeStrategiesEmpty(t *testing.T) {
	if got := optimizeStrategies(nil); got != nil {
		t.Fatalf("optimizeStrategies(nil) = %v, want nil", got)
	}
}

func TestOptimizeStrategiesMergesAndDedups(t *testing.T) {
	raw := []struct {
		Strategy string
		Filters  string
		Provider string
	}{
		{Strategy: "S1", Filters: "F1", Provider: "p1"},
		{Strategy: "S1", Filters: "F1", Provider: "p2"}, // same strategy+filter, new provider
		{Strategy: "S2", Filters: "", Provider: "p3"},   // distinct strategy, empty filter
	}

	got := optimizeStrategies(raw)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (%+v)", len(got), got)
	}

	// Sorted by joined providers: "p1,p2" < "p3".
	s1 := got[0]
	if s1.Strategy != "S1" {
		t.Fatalf("got[0].Strategy = %q, want S1", s1.Strategy)
	}
	if len(s1.Provider) != 2 || s1.Provider[0] != "p1" || s1.Provider[1] != "p2" {
		t.Fatalf("got[0].Provider = %v, want [p1 p2]", s1.Provider)
	}
	if len(s1.Filters) != 1 || s1.Filters[0] != "F1" {
		t.Fatalf("got[0].Filters = %v, want [F1] (deduped)", s1.Filters)
	}

	s2 := got[1]
	if s2.Strategy != "S2" {
		t.Fatalf("got[1].Strategy = %q, want S2", s2.Strategy)
	}
	if len(s2.Filters) != 0 {
		t.Fatalf("got[1].Filters = %v, want empty (blank filter not recorded)", s2.Filters)
	}
}
