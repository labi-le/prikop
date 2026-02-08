package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "contabo",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/contabo/contabo_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://xdmarineshop.gr/index.php?route=index", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://programmer.am/img/logos/types/web-development.png", Threshold: DefaultThreshold, Proto: ProtoTCP, IgnoreStatus: true},
			{URL: "https://nare.am/wp-content/uploads/2020/06/nare_armenia_travel-1280x580.jpg", Threshold: DefaultThreshold, Proto: ProtoTCP, IgnoreStatus: true},
			{URL: "https://metropolis.al/wp-content/uploads/2024/07/Logo-MetroPOLIS-vwhite.png", Threshold: DefaultThreshold, Proto: ProtoTCP, IgnoreStatus: true},
		},
	})
}
