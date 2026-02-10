package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "ovh",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/ovh/ovh_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://eu.api.ovh.com/console/rapidoc-min.js", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://ovh.sfx.ovh/10M.bin", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://proof.ovh.net/files/1Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
			{URL: "https://proof.ovh.net/files/10Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
			{URL: "https://proof.ovh.ca/files/100Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
		},
	})
}
