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
			{URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: 109863},
			{URL: "https://www.bigcartel.com/_next/image?url=https%3A%2F%2Fimages.prismic.io%2Fbigcartel-staging%2FaAkmrfIqRLdaBiNZ_home_hero_lifestyle.png%3Fauto%3Dformat%2Ccompress%26rect%3D0%2C0%2C1600%2C1600%26w%3D1200%26h%3D1200&w=3840&q=75", Threshold: DefaultThreshold},
		},
	})
}
