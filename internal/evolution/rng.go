package evolution

import (
	"math/rand/v2"
	"time"
)

// rng is the single randomness source for evolution and mutation. It is touched
// only from the sequential Evolve/mutate path (RunPhase drives one generation at
// a time, and providers run one at a time via MaxConcurrentProviders), so it
// needs no lock. SetSeed makes the evolution/mutation choices reproducible.
var rng = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano())>>1))

// SetSeed re-seeds evolution's RNG so strategy generation/mutation can be
// replayed. Scope: the orchestrator's evolution only — worker checks run in
// separate containers (their target shuffling is unseeded) and the live network
// is nondeterministic, so a full run is not bit-for-bit reproducible.
func SetSeed(seed uint64) {
	rng = rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}
