package availability

import (
	"prikop/internal/verifier/types"
)

var definitions []types.ProviderDefinition

func registerProvider(p types.ProviderDefinition) {
	definitions = append(definitions, p)
}

func GetProviderDefinition(name string) *types.ProviderDefinition {
	for _, p := range definitions {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

func InitializeProviders(only string) []types.ProviderDefinition {
	if only != "" {
		for _, d := range definitions {
			if d.Name == only {
				return []types.ProviderDefinition{d}
			}
		}
		return nil
	}
	result := make([]types.ProviderDefinition, len(definitions))
	copy(result, definitions)
	return result
}
