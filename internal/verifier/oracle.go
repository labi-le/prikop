package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "oracle",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/oracle/oracle_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://oracle.sfx.ovh/10M.bin", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://oracle.com", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
		},
	})
}
