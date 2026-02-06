package verifier

import "strings"

func NewVerifier(targetGroup string) Verifier {
	// targetGroup может быть "google_tcp", "discord_udp" и т.д.

	if strings.Contains(targetGroup, "discord") {
		return &DiscordVerifier{Mode: targetGroup}
	}
	if strings.Contains(targetGroup, "google") {
		return &GoogleVerifier{Mode: targetGroup}
	}
	// Default
	return &GeneralVerifier{Mode: targetGroup}
}
