package verifier

import (
	"prikop/internal/verifier/discord"
	"prikop/internal/verifier/tcp16_20"
	"prikop/internal/verifier/types"
	"prikop/internal/verifier/youtube"
	"strings"

	"github.com/rs/zerolog"
)

func NewVerifier(targetGroup string, log zerolog.Logger) types.Verifier {
	if strings.Contains(targetGroup, "discord_udp") || strings.Contains(targetGroup, "discord_l7") {
		return &discord.Verifier{Mode: targetGroup, Log: log}
	}
	if strings.Contains(targetGroup, "google") {
		return &youtube.Verifier{Mode: targetGroup, Log: log}
	}

	def := tcp16_20.GetProviderDefinition(targetGroup)
	if def == nil {
		return &GeneralVerifier{
			Mode:    targetGroup,
			Targets: nil,
			Log:     log,
		}
	}

	return &GeneralVerifier{
		Mode:     targetGroup,
		Targets:  def.Targets,
		CIDRPath: def.CIDRFile,
		Log:      log,
	}
}
