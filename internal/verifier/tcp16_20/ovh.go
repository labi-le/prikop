package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(newTCPProvider("ovh",
		"https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/ovh/ovh_plain_ipv4.txt",
		[]types.Target{
			{URL: "https://app.symarobot.com/content/images/logo.png", Threshold: DefaultThreshold, IgnoreStatus: true},
			{URL: "https://proof.ovh.net/files/1Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
			{URL: "https://proof.ovh.net/files/10Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
			{URL: "https://proof.ovh.ca/files/100Mb.dat", Threshold: DefaultThreshold, IgnoreStatus: false},
		},
	))
}
