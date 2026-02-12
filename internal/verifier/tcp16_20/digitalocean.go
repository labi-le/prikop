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
			{URL: "https://genderize.io/images/processed-csv-file-dcfd3e4d6a2c00a7741f8218b2a45a6e.png", Threshold: DefaultThreshold},
			{URL: "https://diaitologos-patra.gr/images/intro_1680.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://opennetworking.org/wp-content/webp-express/webp-images/doc-root/wp-content/uploads/2021/11/iStock-1297506906-1-1.png.webp", IgnoreStatus: true, Threshold: DefaultThreshold},
			{URL: "https://www.linuxserver.io/user/pages/01.home/05._05_documentation/rsz_alfons-morales-410757-unsplash.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://dss375.org/design/html.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
		},
	})
}
