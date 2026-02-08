package verifier

import (
	"strings"
)

func NewVerifier(targetGroup string) Verifier {
	// 1. Built-in verifiers
	if strings.Contains(targetGroup, "discord_udp") || strings.Contains(targetGroup, "discord_l7") {
		return &DiscordVerifier{Mode: targetGroup}
	}
	if strings.Contains(targetGroup, "google") {
		return &GoogleVerifier{Mode: targetGroup}
	}

	// 2. Dynamic Provider verifiers
	if p, ok := GetProvider(targetGroup); ok {
		return &GeneralVerifier{
			Mode:    targetGroup,
			Targets: p.Targets,
		}
	}

	// 3. Fallback (Legacy General)
	return &GeneralVerifier{
		Mode:    targetGroup,
		Targets: GeneralTargets, // Fallback to hardcoded list in data.go
	}
}
