package verifier

import (
	"context"

	"github.com/rs/zerolog"
)

type GoogleVerifier struct {
	Mode string
	log  zerolog.Logger
}

func (v *GoogleVerifier) Name() string {
	return "Google/YT Verifier (" + v.Mode + ")"
}

func (v *GoogleVerifier) Run(ctx context.Context) CheckResult {
	// Для TCP используем домены, которые отдают контент и поддерживают Range
	targets := []Target{
		{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: ProtoTCP},
		{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: ProtoTCP},
		{URL: "https://yt3.ggpht.com/ZaLC1ILAvz614xZii2tjAVsSI_7mpzB4akwdISkhWfxQy6-PW49VNwsjyTtbXY2Ea3nM-0ksQQ4=s88-c-k-c0x00ffffff-no-rj", Threshold: 100, Proto: ProtoTCP}, // Статика
		{URL: "https://i.ytimg.com/vi/LnoptTyhFsE/maxresdefault.jpg", Threshold: 100, IgnoreStatus: true, Proto: ProtoTCP},                                                    // Статика
	}

	// Для UDP (QUIC)
	if v.Mode == "google_udp" {
		targets = []Target{
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: ProtoQUIC},
			{URL: "https://googlevideo.com", Threshold: 1, Proto: ProtoQUIC, IgnoreStatus: true},
		}
	}

	return ExecuteChecks(ctx, v.log, targets)
}
