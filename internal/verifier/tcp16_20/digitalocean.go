package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "digitalocean",
		Gens:       15,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/digitalocean/digitalocean_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://carishealthcare.com/content/uploads/2025/04/Rectangle-105.jpg", Threshold: DefaultThreshold},
			{URL: "https://bohnlawllc.com/wp-content/uploads/sites/27/2024/01/Trusts.jpg", IgnoreStatus: true, Threshold: DefaultThreshold},
			{URL: "https://ecomstal.com/Images/amazon-rank.png", IgnoreStatus: true, Threshold: DefaultThreshold},
			{URL: "https://www.linuxserver.io/user/pages/01.home/05._05_documentation/rsz_alfons-morales-410757-unsplash.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
		},
	})
}
