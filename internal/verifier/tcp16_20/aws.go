package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "aws",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/aws/aws_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://prod-publishers-content.s3.us-east-1.amazonaws.com/media/dhi-hero.jpg", Threshold: 215419, IgnoreStatus: true},
			{URL: "https://panels.twitch.tv/panel-241082439-image-de794bed-6ab0-499c-b888-4c0c71d9b85a", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://a.slack-edge.com/0cedc3b/marketing/img/homepage/true-prospects/hero-revamp/animation/hero@2x.en-GB.webm", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://m.media-amazon.com/images/M/MV5BMzI2MjMyNTgtYTFmYi00NmZkLWI3ZjgtNGFjYWMyODA2MWUxXkEyXkFqcGc@._V1_FMjpg_UY2222_.jpg", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://www.herokucdn.com/malibu/latest/sprite.svg", Threshold: DefaultThreshold, IgnoreStatus: true},
		},
	})
}
