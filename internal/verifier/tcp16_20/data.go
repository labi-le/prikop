package tcp16_20

import (
	"fmt"
	"path/filepath"
	"prikop/internal/verifier/types"
)

const DefaultThreshold = 64 * 1024

const gens = 5

const TargetsDir = "/app/targets"

var (
	definitions []types.ProviderDefinition
)

func newTCPProvider(name string, cidrSource string, targets []types.Target) types.ProviderDefinition {
	cidrPath := filepath.Join(TargetsDir, name+"-cidr.txt")
	return types.ProviderDefinition{
		Name:       name,
		Gens:       gens,
		CIDRSource: cidrSource,
		Filters:    fmt.Sprintf("--filter-tcp=80,443 --ipset=%s", cidrPath),
		Targets:    targets,
	}
}

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
