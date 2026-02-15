package availability

import (
	"fmt"
	"prikop/internal/verifier/types"
)

const googleHostListPath = "/app/targets"

func init() {
	registerProvider(types.ProviderDefinition{
		Name:    "google_tcp",
		Gens:    10,
		Filters: fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", googleHostListPath),
		Targets: []types.Target{
			{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://yt3.ggpht.com/ZaLC1ILAvz614xZii2tjAVsSI_7mpzB4akwdISkhWfxQy6-PW49VNwsjyTtbXY2Ea3nM-0ksQQ4=s88-c-k-c0x00ffffff-no-rj", Threshold: 100, Proto: types.ProtoTCP},
			{URL: "https://i.ytimg.com/vi/LnoptTyhFsE/maxresdefault.jpg", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
		},
	})

	registerProvider(types.ProviderDefinition{
		Name:    "google_udp",
		Gens:    10,
		Filters: fmt.Sprintf("--filter-udp=443 --filter-l7=quic --hostlist=%s/google.txt", googleHostListPath),
		Targets: []types.Target{
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoQUIC},
			{URL: "https://googlevideo.com", Threshold: 1, Proto: types.ProtoQUIC, IgnoreStatus: true},
		},
	})
}
