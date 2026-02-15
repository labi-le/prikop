package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(newTCPProvider("scaleway",
		"https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/scaleway/scaleway_plain_ipv4.txt",
		[]types.Target{
			{URL: "https://www.velivole.fr/img/header.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://www.moobicom.ci/assets/slider1.jpg", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://laboratoire-ccd.com/wp-content/uploads/Gyndelta_canneberge_1mois_3mois.png", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
		},
	))
}
