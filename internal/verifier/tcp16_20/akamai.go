package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "akamai",
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/akamai/akamai_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://www.roxio.com/static/roxio/images/products/creator/nxt9/call-action-footer-bg.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://media-assets.stryker.com/is/image/stryker/gateway_1?$max_width_1410$", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://cdn-front.freepik.com/home/anon-rvmp/spaces/spaces_op.webm", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://newfold.scene7.com/is/image/NewfoldDigital/Hero__desktop?ts=1766088635719&dpr=off&fmt=avif-alpha", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
		},
	})
}
