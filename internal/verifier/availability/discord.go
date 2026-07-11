package availability

import (
	"prikop/internal/verifier/types"
)

// Discord has two legs; only the chat/web leg is an nfqws2 GA provider here.
//
//  1. discord_tcp — HTTPS/TLS to discord.com, its API and CDN (chat + web).
//  2. voice       — NOT a GA provider. Discord mandates the DAVE (E2EE) protocol
//     for all non-stage voice, so no bot/active probe can complete the voice
//     handshake; the only test is sniffing a REAL call. That lives in
//     orchestrator.runVoiceCapture, run by `-provider discord_voice` (host-level,
//     needs root; see also voice-dpi-test.sh for the standalone form).
func init() {
	registerProvider(types.ProviderDefinition{
		Name:             "discord_tcp",
		Gens:             5,
		Proto:            "tcp",
		SuccessThreshold: 0.95,
		Targets: []types.Target{
			{URL: "https://discord.com", Threshold: 5000, Proto: types.ProtoTCP},
			{URL: "https://discord.com/api/v9/gateway", Threshold: 1000, Proto: types.ProtoTCP},
			{URL: "https://gateway.discord.gg", Threshold: 1000, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png", Threshold: 1000, IgnoreStatus: true, Proto: types.ProtoTCP},
		},
	})
}
