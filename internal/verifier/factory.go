package verifier

import (
	"strings"

	"github.com/rs/zerolog"
)

func NewVerifier(targetGroup string, log zerolog.Logger) Verifier {
	// 1. Built-in verifiers
	if strings.Contains(targetGroup, "discord_udp") || strings.Contains(targetGroup, "discord_l7") {
		return &DiscordVerifier{Mode: targetGroup, log: log}
	}
	if strings.Contains(targetGroup, "google") {
		return &GoogleVerifier{Mode: targetGroup, log: log}
	}

	// 2. Dynamic Provider verifiers
	if p, ok := GetProvider(targetGroup); ok {
		return &GeneralVerifier{
			Mode:    targetGroup,
			Targets: p.Targets,
			log:     log,
		}
	}

	// 3. Fallback (Legacy General)
	return &GeneralVerifier{
		Mode:    targetGroup,
		Targets: GeneralTargets, // Fallback to hardcoded list in data.go
		log:     log,
	}
}
