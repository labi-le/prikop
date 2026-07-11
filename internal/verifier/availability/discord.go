package availability

import (
	"prikop/internal/verifier/types"
)

// Discord's app path is several distinct Cloudflare-fronted domains that, on a
// real DPI, do NOT all yield to one desync. So — like flowseal/Zapret-Manager,
// which use a separate profile per domain — each is its own GA provider that
// finds and pins its own winning strategy (one target, SuccessThreshold 1.0),
// scoped by --hostlist-domains so the emitted config desyncs only that domain.
//
// Deliberately excluded:
//   - discord.com apex: not on the app's path, and throttled even under a working
//     zapret2 — a false anchor that made the old single discord_tcp unwinnable.
//   - voice: Discord mandates DAVE (E2EE) for non-stage voice, so no active probe
//     completes the handshake; it is verified by sniffing a real call
//     (orchestrator.runVoiceCapture, -provider discord_voice). discord_media here
//     only checks that the media domain's TLS reaches through the DPI on 443.
func init() {
	discord := func(name, hostlistDomain, url string) types.ProviderDefinition {
		return types.ProviderDefinition{
			Name:             name,
			Gens:             5,
			Proto:            "tcp",
			SuccessThreshold: 1.0,
			Filters:          "--hostlist-domains=" + hostlistDomain,
			Targets: []types.Target{
				{URL: url, IgnoreStatus: true, Proto: types.ProtoTCP},
			},
		}
	}
	registerProvider(discord("discord_gateway", "discord.gg", "https://gateway.discord.gg"))
	registerProvider(discord("discord_api", "discord.com", "https://discord.com/api/v9/gateway"))
	registerProvider(discord("discord_cdn", "discordapp.com", "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png"))
	registerProvider(discord("discord_media", "discord.media", "https://discord.media"))
}
