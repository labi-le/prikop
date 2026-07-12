package orchestrator

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// genRecord is one generation's best candidate, for the --report JSON.
type genRecord struct {
	Gen        int     `json:"gen"`
	Population int     `json:"population"`
	Best       string  `json:"best_strategy"`
	Score      float64 `json:"best_score"`
	Success    int     `json:"best_success"`
	Total      int     `json:"best_total"`
}

// providerRecord is the full GA trace for one provider.
type providerRecord struct {
	Provider    string      `json:"provider"`
	Proto       string      `json:"proto"`
	Filters     string      `json:"filters"`
	Outcome     string      `json:"outcome"` // winner | reachable_without_bypass | no_strategy
	Winner      string      `json:"winner,omitempty"`
	Generations []genRecord `json:"generations,omitempty"`
}

// Reporter accumulates per-generation and per-provider results for an optional
// JSON run report (-report). All methods are nil-safe, so callers hold a
// possibly-nil *Reporter and never branch on it.
type Reporter struct {
	mu    sync.Mutex
	provs map[string]*providerRecord
	order []string
}

func NewReporter() *Reporter {
	return &Reporter{provs: map[string]*providerRecord{}}
}

// get returns (creating if needed) the record for a provider. Caller holds mu.
func (r *Reporter) get(name, proto, filters string) *providerRecord {
	pr, ok := r.provs[name]
	if !ok {
		pr = &providerRecord{Provider: name, Proto: proto, Filters: filters}
		r.provs[name] = pr
		r.order = append(r.order, name)
	}
	return pr
}

func (r *Reporter) recordGen(name, proto, filters string, rec genRecord) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pr := r.get(name, proto, filters)
	pr.Generations = append(pr.Generations, rec)
}

func (r *Reporter) recordOutcome(name, proto, filters, outcome, winner string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pr := r.get(name, proto, filters)
	pr.Outcome = outcome
	pr.Winner = winner
}

// Write marshals the report to path. Nil-safe (no-op on a nil Reporter).
func (r *Reporter) Write(path string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	out := struct {
		GeneratedAt string            `json:"generated_at"`
		Providers   []*providerRecord `json:"providers"`
	}{GeneratedAt: time.Now().Format(time.RFC3339)}
	for _, name := range r.order {
		out.Providers = append(out.Providers, r.provs[name])
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
