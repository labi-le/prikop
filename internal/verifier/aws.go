package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "aws",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/aws/aws_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://www.getscope.com/assets/fonts/fa-solid-900.woff2", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: ProtoTCP},
			{URL: "https://corp.kaltura.com/wp-content/cache/min/1/wp-content/themes/airfleet/dist/styles/theme.css", Threshold: 215419, IgnoreStatus: true},
			{URL: "https://images.laracasts.com/reviews/jess-archer.jpg", Threshold: 215419, IgnoreStatus: true},
			{URL: "https://ds-cdn.prod-east.frontend.public.atl-paas.net/assets/fonts/atlassian-sans/v3/AtlassianSans-latin.woff2", Threshold: 215419, IgnoreStatus: true},
		},
	})
}
