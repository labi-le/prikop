package availability

import (
	"prikop/internal/verifier/types"
)

// Discord's app path is several distinct Cloudflare-fronted domains that, on a
// real DPI, do NOT yield to one shared desync — so, like flowseal/Zapret-Manager
// which use a separate profile per domain, each is its own GA provider that pins
// its own winning strategy, scoped by --hostlist-domains so the emitted rule
// desyncs only that domain.
//
// These are HandshakeOnly checks: the symptom is "the client won't load /
// discord.com won't open", i.e. the TLS handshake must survive the DPI. The
// default 64 KiB POST probe is a heavy-upload stress test the DPI throttles even
// under a working bypass, so it is skipped here (see Target.HandshakeOnly).
//
// Voice is not covered: Discord mandates DAVE (E2EE) for non-stage voice, so no
// active probe completes the handshake — it is verified by sniffing a real call
// (orchestrator.runVoiceCapture, -provider discord_voice). discord_media only
// checks the media domain's TLS reaches through the DPI on 443.
func init() {
	discord := func(name, hostlistDomain string, urls ...string) types.ProviderDefinition {
		targets := make([]types.Target, len(urls))
		for i, u := range urls {
			targets[i] = types.Target{URL: u, IgnoreStatus: true, HandshakeOnly: true, Proto: types.ProtoTCP}
		}
		return types.ProviderDefinition{
			Name:             name,
			Gens:             5,
			Proto:            "tcp",
			SuccessThreshold: 1.0,
			Filters:          "--hostlist-domains=" + hostlistDomain,
			Targets:          targets,
		}
	}
	registerProvider(discord("discord_web", "discord.com", "https://discord.com", "https://discord.com/api/v9/gateway"))
	registerProvider(discord("discord_gateway", "discord.gg", "https://gateway.discord.gg"))
	registerProvider(discord("discord_cdn", "discordapp.com", "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png"))
	registerProvider(discord("discord_media", "discord.media", "https://discord.media"))
}
