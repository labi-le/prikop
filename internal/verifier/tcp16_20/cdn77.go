package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(newTCPProvider("cdn77",
		"https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cdn77/cdn77_plain_ipv4.txt",
		[]types.Target{
			{URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://arweave.net", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://static-cdn77.xvideos-cdn.com/v3/img/skins/default/logo/events/xvideos.white.olympic.svg", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://forum.xnxx.com/styles/logo_xnxx_valentines.png", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
		},
	))
}
