package tcp16_20

import (
	"prikop/internal/verifier/types"
)

const DefaultThreshold = 64 * 1024

const gens = 5

var (
	definitions []types.ProviderDefinition
)

func registerProvider(p types.ProviderDefinition) {
	//if p.Name != "cloudflare" {
	//	return
	//}
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
