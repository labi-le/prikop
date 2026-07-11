package availability

import (
	"prikop/internal/verifier/types"
)

// Discord verification has two legs, so a run covers both the chat/web path and
// the voice path:
//
//  1. discord_tcp   — HTTPS/TLS to discord.com, its API and CDN (chat + web).
//  2. discord_voice — UDP/STUN reachability, the transport Discord voice rides
//     on. checker.checkSTUN sends a STUN Binding Request and expects a Binding
//     Success Response.
//
// Why discord_voice probes PUBLIC STUN servers and not discord.media directly:
// Discord's own <region>.discord.media voice servers are SESSION-GATED — they
// reply only to the client's authenticated session socket (Discord IP-Discovery
// carries the session SSRC), so a bare STUN Binding Request to them always times
// out even while a real call works (verified against live voice servers). A
// public STUN server, by contrast, answers anyone, so this leg cleanly measures
// whether UDP + STUN round-trips survive the DPI/zapret path — the mechanism
// Discord voice needs. For a definitive Discord-voice check, capture a live call
// on the router (`tcpdump -ni wan 'udp[12:4] = 0x2112a442'`, look for
// bidirectional packets to <server>:5000x) or use `cmd/discord-voice-test`.
var discordEnabled = true

func init() {
	if !discordEnabled {
		return
	}

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

	registerProvider(types.ProviderDefinition{
		Name:             "discord_voice",
		Gens:             5,
		Proto:            "udp",
		SuccessThreshold: 1.0,
		Targets: []types.Target{
			{URL: "stun.l.google.com:19302", Proto: types.ProtoSTUN},
			{URL: "stun1.l.google.com:19302", Proto: types.ProtoSTUN},
			{URL: "stun.cloudflare.com:3478", Proto: types.ProtoSTUN},
		},
	})
}
