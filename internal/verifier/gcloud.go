package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "gcloud",
		Gens:       gens,
		CIDRSource: "https://www.gstatic.com/ipranges/cloud.json",
		Targets: []Target{
			{URL: "https://api.usercentrics.eu/gvl/v3/en.json", Threshold: 176277, IgnoreStatus: true},
			{URL: "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://ipwhoisinfo.com&size=128", Threshold: 176277, IgnoreStatus: true},
			{URL: "https://www.latlong.net/photos/tb-return-to-silent-hill.jpg", Threshold: 176277, IgnoreStatus: true},
			{URL: "https://cromwell-intl.com/pictures/moscow-0084.jpg", Threshold: 176277, IgnoreStatus: true},
		},
	})
}
