package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "fastly",
		Gens:       gens,
		CIDRSource: "https://github.com/123jjck/cdn-ip-ranges/raw/refs/heads/main/fastly/fastly_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://www.jetblue.com/footer/footer-element-es2015.js", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://ssl.p.jwpcdn.com/player/v/8.40.5/bidding.js", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://raw.githubusercontent.com/labi-le/belphegor/refs/heads/main/logo.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://s.pinimg.com/webapp/home-img-1-7ca21c82.png", Threshold: DefaultThreshold, IgnoreStatus: true},
		},
	})
}
