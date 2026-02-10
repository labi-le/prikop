package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "cdn77",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cdn77/cdn77_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://arweave.net", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://static-cdn77.xvideos-cdn.com/v3/img/skins/default/logo/events/xvideos.white.olympic.svg", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://static.generated.photos/vue-static/genyou/images/hero/hero-1.webp", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
		},
	})
}
