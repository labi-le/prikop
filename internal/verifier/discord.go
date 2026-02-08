package verifier

import (
	"context"
)

type DiscordVerifier struct {
	Mode string // discord_tcp, discord_udp, discord_l7
}

func (v *DiscordVerifier) Name() string {
	return "Discord Verifier (" + v.Mode + ")"
}

func (v *DiscordVerifier) Run(ctx context.Context) CheckResult {
	// Default TCP targets
	targets := []Target{
		{URL: "https://discord.com", Threshold: 5000, Proto: ProtoTCP},
		{URL: "https://discord.com/assets/b135ff6c8e091b43.mp3", Threshold: 1000, Proto: ProtoTCP},
		{URL: "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png", Threshold: 1000, Proto: ProtoTCP},
		{URL: "https://support.discord.com/system/photos/1501104751241/profile_image_115979785972_678183.jpg", Threshold: 1000, Proto: ProtoTCP},
		{URL: "https://status.discord.com/api/v2/scheduled-maintenances/active.json", Threshold: 1000, Proto: ProtoTCP},
	}

	if v.Mode == "discord_udp" {
		targets = []Target{
			{URL: "https://discord.com", Threshold: 1000, Proto: ProtoQUIC},
			{URL: "https://gateway.discord.gg", Threshold: 1000, Proto: ProtoQUIC},
		}
	}

	if v.Mode == "discord_l7" {
		// STUN targets. Format: "ip:port"
		targets = []Target{
			{URL: "50.7.85.202:50001", Proto: ProtoSTUN},
			{URL: "50.7.85.202:50002", Proto: ProtoSTUN},
			{URL: "162.159.138.232:443", Proto: ProtoSTUN},
			{URL: "66.22.244.70:50001", Proto: ProtoSTUN},
			{URL: "66.22.244.70:50002", Proto: ProtoSTUN},
		}
	}

	return ExecuteChecks(ctx, v.Mode, targets)
}
