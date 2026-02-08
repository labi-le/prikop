package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "cdn77",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cdn77/cdn77_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://arweave.net", Threshold: DefaultThreshold, Proto: ProtoTCP},
			{URL: "https://static-cdn77.xvideos-cdn.com/v3/img/skins/default/logo/events/xvideos.white.olympic.svg", Threshold: DefaultThreshold, Proto: ProtoTCP, IgnoreStatus: true},
			{URL: "https://static.generated.photos/vue-static/genyou/images/hero/hero-1.webp", Threshold: DefaultThreshold, Proto: ProtoTCP, IgnoreStatus: true},
		},
	})
}
