package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "contabo",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/contabo/contabo_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://programmer.am/img/logos/types/web-development.png", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://nare.am/wp-content/uploads/2020/06/nare_armenia_travel-1280x580.jpg", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://metropolis.al/wp-content/uploads/2024/07/Logo-MetroPOLIS-vwhite.png", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
		},
	})
}
