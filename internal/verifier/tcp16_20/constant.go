package tcp16_20

import (
	"prikop/internal/verifier/types"
)

func init() {
	registerProvider(types.ProviderDefinition{
		Name:       "constant", // vultr
		Gens:       gens,
		CIDRSource: "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/constant/constant_plain_ipv4.txt",
		Targets: []types.Target{
			{URL: "https://cdn.xuansiwei.com/common/lib/font-awesome/4.7.0/fontawesome-webfont.woff2?v=4.7.0", Threshold: DefaultThreshold, IgnoreStatus: true, Proto: types.ProtoTCP},
			{URL: "https://viaanabel.al/static/banners/banner_1001_v3_sq.jpg", Threshold: DefaultThreshold, Proto: types.ProtoTCP},
			{URL: "https://ctcu.com.ar/download/novedades.imagen.886cc162ee9fa24a.576861747341707020496d61676520323032352d31322d31312061742030382e35322e33362e6a706567.jpeg?_signature=liCl4x7kRPl4p8Tk4ivx3p-82Ig", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
			{URL: "https://smitsrl.com/arena-smit.jpeg", Threshold: DefaultThreshold, Proto: types.ProtoTCP, IgnoreStatus: true},
		},
	})
}
