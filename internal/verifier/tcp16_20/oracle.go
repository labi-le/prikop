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
			{URL: "https://oracle.sfx.ovh/10M.bin", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "http://40.233.0.95/assets/bundle.538a44e1.js", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://k.860617.xyz/static/app/dist/main.js", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://oracle.afyh.space/assets/bundle.538a44e1.js", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
		},
	})
}
