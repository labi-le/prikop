package tcp16_20

import (
	"prikop/internal/verifier/types"
)

const DefaultThreshold = 64 * 1024

const gens = 5

var (
	definitions    []types.ProviderDefinition
)

func registerProvider(p types.ProviderDefinition) {
	definitions = append(definitions, p)
}

func GetProviderTargets(name string) []types.Target {
	for _, p := range definitions {
		if p.Name == name {
			return p.Targets
		}
	}
	return nil
}

func GetProviderDefinition(name string) *types.ProviderDefinition {
	for _, p := range definitions {
		if p.Name == name {
			return &p
		}
	}
	return nil
}
