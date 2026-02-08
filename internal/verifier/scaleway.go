package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "scaleway",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/scaleway/scaleway_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://www.velivole.fr/img/header.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://ping.online.net/1Mo.dat", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "http://elec-martin.fr/", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://www.moobicom.ci/assets/slider1.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://laboratoire-ccd.com", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
		},
	})
}
