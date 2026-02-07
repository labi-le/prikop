package verifier

import (
	"context"
)

type DiscordVerifier struct {
	Mode string // discord_tcp, discord_udp
}

func (v *DiscordVerifier) Name() string {
	return "Discord Verifier (" + v.Mode + ")"
}

func (v *DiscordVerifier) Run(ctx context.Context) CheckResult {
	targets := []Target{
		{URL: "https://discord.com", Threshold: 5000},
		{URL: "https://discord.com/assets/b135ff6c8e091b43.mp3", Threshold: 1000},
		{URL: "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png", Threshold: 1000},
		{URL: "https://support.discord.com/system/photos/1501104751241/profile_image_115979785972_678183.jpg", Threshold: 1000},
		{URL: "https://status.discord.com/api/v2/scheduled-maintenances/active.json", Threshold: 1000},
	}

	if v.Mode == "discord_udp" {
		targets = []Target{
			{URL: "https://discord.com", Threshold: 1000, Proto: "quic"},
			{URL: "https://canary.discord.com", Threshold: 1000, Proto: "quic"},
		}
	}

	return ExecuteChecks(ctx, targets)
}
