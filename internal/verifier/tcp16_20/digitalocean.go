package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "digitalocean",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/digitalocean/digitalocean_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://genderize.io/", Threshold: 195612, IgnoreStatus: true},
			{URL: "https://snipaste.com", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://opennetworking.org/wp-content/uploads/2017/06/onf-logo.jpg", Threshold: 195612, IgnoreStatus: true},
			{URL: "https://callfilter.app/img/phone.png", Threshold: 195612, IgnoreStatus: true},
		},
	})
}
