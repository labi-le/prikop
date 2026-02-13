package discord

import (
	"context"
	"prikop/internal/verifier/checker"
	"prikop/internal/verifier/types"

	"github.com/rs/zerolog"
)

type Verifier struct {
	Mode string // discord_tcp, discord_udp, discord_l7
	Log  zerolog.Logger
}

func (v *Verifier) Name() string {
	return "Discord Verifier (" + v.Mode + ")"
}

func (v *Verifier) Run(ctx context.Context) types.CheckResult {
	// Default TCP targets
	targets := []types.Target{
		{URL: "https://discord.com", Threshold: 5000, Proto: types.ProtoTCP},
		{URL: "https://discord.com/assets/b135ff6c8e091b43.mp3", Threshold: 1000, Proto: types.ProtoTCP},
		{URL: "https://cdn.discordapp.com/clan-badges/700478419527270430/dea97e909a0211e2479d75cd11c2ec41.png", Threshold: 1000, Proto: types.ProtoTCP},
		{URL: "https://support.discord.com/system/photos/1501104751241/profile_image_115979785972_678183.jpg", Threshold: 1000, Proto: types.ProtoTCP},
		{URL: "https://status.discord.com/api/v2/scheduled-maintenances/active.json", Threshold: 1000, Proto: types.ProtoTCP},
	}

	if v.Mode == "discord_udp" {
		targets = []types.Target{
			{URL: "https://discord.com", Threshold: 1000, Proto: types.ProtoQUIC},
			{URL: "https://gateway.discord.gg", Threshold: 1000, Proto: types.ProtoQUIC},
		}
	}

	if v.Mode == "discord_l7" {
		// STUN targets. Format: "ip:port"
		targets = []types.Target{
			{URL: "50.7.85.202:50001", Proto: types.ProtoSTUN},
			{URL: "50.7.85.202:50002", Proto: types.ProtoSTUN},
			{URL: "162.159.138.232:443", Proto: types.ProtoSTUN},
			{URL: "66.22.244.70:50001", Proto: types.ProtoSTUN},
			{URL: "66.22.244.70:50002", Proto: types.ProtoSTUN},
		}
	}

	return checker.ExecuteChecks(ctx, v.Log, targets, "")
}
