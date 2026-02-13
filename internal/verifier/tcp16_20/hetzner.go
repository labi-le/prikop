package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "hetzner",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/hetzner/hetzner_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://accesorioscelular.com/tienda/css/plugins.css", Threshold: DefaultThreshold},
			{URL: "https://251b5cd9.nip.io/1MB.bin", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://nioges.com/libs/fontawesome/webfonts/fa-solid-900.woff2", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://5fd8bdae.nip.io/1MB.bin", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://ash-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: types.ProtoTCP}, // Ashburn, US
		},
	})
}
