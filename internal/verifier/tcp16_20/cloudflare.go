package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "cloudflare",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cloudflare/cloudflare_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://img.wzstats.gg/cleaver/gunFullDisplay", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://genshin.jmp.blue/characters/all#", Threshold: 104319, IgnoreStatus: true},
			{URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: 109863, IgnoreStatus: true},
			{URL: "https://www.bigcartel.com/", Threshold: 79655, IgnoreStatus: true},
		},
	})
}
