package availability

import (
	"fmt"
	"prikop/internal/verifier/types"
)

const googleHostListPath = "/app/targets"

// YouTube test domains + methodology adopted from Zapret-Manager
// (github.com/StressOzz/Zapret-Manager, check_access): the hosts that actually
// gate video playback are the googlevideo CDN edges rr1---sn-*, not the
// youtube.com front alone. Probe the front plus several rr1 edges — all must
// stay reachable for smooth playback — so evolution optimizes for real video
// delivery rather than the landing page or peripheral image assets.
func init() {
	registerProvider(types.ProviderDefinition{
		Name:             "google_tcp",
		Gens:             2,
		Proto:            "tcp",
		SuccessThreshold: 0.95,
		Filters:          fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", googleHostListPath),
		Targets: []types.Target{
			{URL: "https://youtube.com", Threshold: 100, Proto: types.ProtoTCP},
			{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://rr1---sn-gvnuxaxjvh-jx3l.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://rr1---sn-gvnuxaxjvh-jx3s.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoTCP},
		},
	})

	registerProvider(types.ProviderDefinition{
		Name:             "google_udp",
		Gens:             2,
		Proto:            "udp",
		SuccessThreshold: 0.95,
		Filters:          fmt.Sprintf("--filter-udp=443 --filter-l7=quic --hostlist=%s/google.txt", googleHostListPath),
		Targets: []types.Target{
			{URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoQUIC},
			{URL: "https://manifest.googlevideo.com/100MB", Threshold: 100, IgnoreStatus: true, Proto: types.ProtoQUIC},
		},
	})
}
