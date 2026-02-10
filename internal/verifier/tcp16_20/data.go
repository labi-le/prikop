package tcp16_20

import (
	"prikop/internal/verifier/types"
)

const DefaultThreshold = 64 * 1024

const gens = 5

var (
	GeneralTargets []types.Target
	definitions    []types.ProviderDefinition
)

func registerProvider(p types.ProviderDefinition) {
	definitions = append(definitions, p)
	GeneralTargets = append(GeneralTargets, p.Targets...)
}
