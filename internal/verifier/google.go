package verifier

import "context"

type GoogleVerifier struct {
	Mode string
}

func (v *GoogleVerifier) Name() string {
	return "Google/YT Verifier (" + v.Mode + ")"
}

func (v *GoogleVerifier) Run(ctx context.Context) CheckResult {
	// Для TCP используем домены, которые отдают контент и поддерживают Range
	targets := []Target{
		{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true},
		{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true},
		{URL: "https://yt3.ggpht.com/ZaLC1ILAvz614xZii2tjAVsSI_7mpzB4akwdISkhWfxQy6-PW49VNwsjyTtbXY2Ea3nM-0ksQQ4=s88-c-k-c0x00ffffff-no-rj", Threshold: 100}, // Статика
		{URL: "https://i.ytimg.com/an_webp/16D-7yvJHAQ/mqdefault_6s.webp?du=3000&sqp=CJzcl8wG&rs=AOn4CLBrtFJ3SJihnzTi-yXmaOXaUsznyg", Threshold: 100},        // Статика
	}

	// Для UDP (QUIC)
	if v.Mode == "google_udp" {
		targets = []Target{
			{URL: "https://rr3---sn-4g5ednsd.googlevideo.com", Threshold: 1000, Proto: "quic", IgnoreStatus: true},
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true},
			{URL: "https://googlevideo.com", Threshold: 1, Proto: "quic", IgnoreStatus: true},
		}
	}

	return runParallelChecks(ctx, targets)
}
