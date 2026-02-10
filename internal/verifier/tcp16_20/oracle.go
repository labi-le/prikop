package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "oracle",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/oracle/oracle_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://oracle.sfx.ovh/10M.bin", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://oracle.com", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
		},
	})
}
