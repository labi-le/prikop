package verifier

const DefaultThreshold = 64 * 1024

const gens = 20

var (
	GeneralTargets  []Target
	StaticProviders []ProviderDefinition
)

func registerProvider(p ProviderDefinition) {
	StaticProviders = append(StaticProviders, p)
	GeneralTargets = append(GeneralTargets, p.Targets...)
}
