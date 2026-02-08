package verifier

func init() {
	registerProvider(ProviderDefinition{
		Name:       "fastly",
		Gens:       gens,
		CIDRSource: "https://github.com/123jjck/cdn-ip-ranges/raw/refs/heads/main/fastly/fastly_plain_ipv4.txt",
		Targets: []Target{
			{URL: "https://www.jetblue.com/footer/footer-element-es2015.js", Threshold: 77597, IgnoreStatus: true},
			{URL: "https://ssl.p.jwpcdn.com/player/v/8.40.5/bidding.js", Threshold: 84086, IgnoreStatus: true},
			{URL: "https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/Strategies_For_Youtube.md", Threshold: 84086, IgnoreStatus: true},
			{URL: "https://s.pinimg.com/webapp/home-img-1-7ca21c82.png", Threshold: 84086, IgnoreStatus: true},
		},
	})
}
