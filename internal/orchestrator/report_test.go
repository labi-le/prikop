package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReporterWrite(t *testing.T) {
	r := NewReporter()
	r.recordGen("p1", "tcp", "--filter-tcp=443", genRecord{Gen: 0, Population: 10, Best: "strat-a", Score: 42, Success: 1, Total: 1})
	r.recordGen("p1", "tcp", "--filter-tcp=443", genRecord{Gen: 1, Population: 20, Best: "strat-b", Score: 55, Success: 2, Total: 2})
	r.recordOutcome("p1", "tcp", "--filter-tcp=443", "winner", "strat-b")
	r.recordOutcome("p2", "tcp", "", "reachable_without_bypass", "")

	path := filepath.Join(t.TempDir(), "report.json")
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Providers []struct {
			Provider    string `json:"provider"`
			Outcome     string `json:"outcome"`
			Winner      string `json:"winner"`
			Generations []struct {
				Gen int `json:"gen"`
			} `json:"generations"`
		} `json:"providers"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	if len(got.Providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(got.Providers))
	}
	p1 := got.Providers[0]
	if p1.Provider != "p1" || p1.Outcome != "winner" || p1.Winner != "strat-b" {
		t.Fatalf("p1 = %+v, want winner strat-b", p1)
	}
	if len(p1.Generations) != 2 || p1.Generations[1].Gen != 1 {
		t.Fatalf("p1 generations = %+v, want 2 recorded", p1.Generations)
	}
	if got.Providers[1].Outcome != "reachable_without_bypass" {
		t.Fatalf("p2 outcome = %q, want reachable_without_bypass", got.Providers[1].Outcome)
	}
}

// TestReporterNilSafe locks that a nil Reporter (no -report) is a safe no-op,
// so callers never have to branch on it.
func TestReporterNilSafe(t *testing.T) {
	var r *Reporter
	r.recordGen("p", "tcp", "", genRecord{})
	r.recordOutcome("p", "tcp", "", "winner", "s")
	if err := r.Write(filepath.Join(t.TempDir(), "x.json")); err != nil {
		t.Fatalf("nil Write returned %v, want nil", err)
	}
}
