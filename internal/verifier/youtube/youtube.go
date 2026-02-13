package youtube

import (
	"context"
	"prikop/internal/verifier/checker"
	"prikop/internal/verifier/types"

	"github.com/rs/zerolog"
)

type Verifier struct {
	Mode string
	Log  zerolog.Logger
}

func (v *Verifier) Name() string {
	return "Google/YT Verifier (" + v.Mode + ")"
}

func (v *Verifier) Run(ctx context.Context) types.CheckResult {
	targets := []types.Target{
		{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
		{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
		{URL: "https://yt3.ggpht.com/ZaLC1ILAvz614xZii2tjAVsSI_7mpzB4akwdISkhWfxQy6-PW49VNwsjyTtbXY2Ea3nM-0ksQQ4=s88-c-k-c0x00ffffff-no-rj", Threshold: 100, Proto: types.ProtoTCP},
		{URL: "https://i.ytimg.com/vi/LnoptTyhFsE/maxresdefault.jpg", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
	}

	if v.Mode == "google_udp" {
		targets = []types.Target{
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoQUIC},
			{URL: "https://googlevideo.com", Threshold: 1, Proto: types.ProtoQUIC, IgnoreStatus: true},
		}
	}

	return checker.ExecuteChecks(ctx, v.Log, targets, "")
}
