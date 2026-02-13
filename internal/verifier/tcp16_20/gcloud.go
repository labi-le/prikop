package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "gcloud",
		Gens:       gens,
		CIDRSource: "https://www.gstatic.com/ipranges/cloud.json",
		Targets: []types.Target{
			{URL: "https://api.usercentrics.eu/gvl/v3/en.json", Threshold: 176277, IgnoreStatus: true},
			{URL: "https://www.latlong.net/img/latlong-products2.jpeg", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://cromwell-intl.com/fonts/hammersmithone.ttf", Threshold: 176277, IgnoreStatus: true},
		},
	})
}
