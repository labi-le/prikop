package verifier

import (
	"prikop/internal/verifier/availability"
	"prikop/internal/verifier/tcp16_20"
	"prikop/internal/verifier/types"

	"github.com/rs/zerolog"
)

func NewVerifier(targetGroup string, log zerolog.Logger) types.Verifier {
	if def := availability.GetProviderDefinition(targetGroup); def != nil {
		return &GeneralVerifier{Mode: targetGroup, Targets: def.Targets, Log: log}
	}

	for _, def := range tcp16_20.Cases() {
		if def.Name != targetGroup {
			continue
		}
		return &GeneralVerifier{Mode: targetGroup, Targets: def.Targets, CIDRPath: def.CIDRFile, Log: log}

	}

	return &GeneralVerifier{Mode: targetGroup, Targets: nil, Log: log}
}
