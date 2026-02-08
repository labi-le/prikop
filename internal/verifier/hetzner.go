package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "hetzner",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/hetzner/hetzner_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://accesorioscelular.com/tienda/css/plugins.css", Threshold: 162646, IgnoreStatus: true},
			{URL: "https://251b5cd9.nip.io/1MB.bin", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://nioges.com/libs/fontawesome/webfonts/fa-solid-900.woff2", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://5fd8bdae.nip.io/1MB.bin", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},

			{URL: "https://nbg1-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP}, // Nuremberg, DE
			{URL: "https://fsn1-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP}, // Falkenstein, DE
			{URL: "https://hel1-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP}, // Helsinki, FI
			{URL: "https://ash-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP},  // Ashburn, US
			{URL: "https://hil-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP},  // Hillsboro, US
			{URL: "https://sin-speed.hetzner.com/100MB.bin", Threshold: DefaultThreshold, IgnoreStatus: false, Proto: ProtoTCP},  // Singapore
		},
	})
}
