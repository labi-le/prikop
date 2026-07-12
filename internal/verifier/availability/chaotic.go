package availability

import "prikop/internal/verifier/types"

// Chaotic-AUR (chaotic.cx) is an Arch binary repo, but its packages are actually
// served from builds.garudalinux.org — cdn-mirror.chaotic.cx 303-redirects there.
// That origin (garudalinux.org) is the hosting "provider" the DPI kills, so
// pacman can't fetch packages ("cache is dead"). We test the real origin directly
// so evolution finds a working strategy for it, scoped to BOTH domains via
// --hostlist-domains (the mirror entry chaotic.cx + the origin garudalinux.org).
//
// Target: chaotic-aur.db.tar.zst — the repo database (stable name, always present,
// ~660 KB), pulled the same "fetch the real URL + size" way as nixos_cache:
//
//	curl -IL https://cdn-mirror.chaotic.cx/chaotic-aur/x86_64/chaotic-aur.db.tar.zst
//	  -> 200 https://builds.garudalinux.org/repos/chaotic-aur/x86_64/chaotic-aur.db.tar.zst
//	  content-length: 676248
func init() {
	registerProvider(types.ProviderDefinition{
		Name:             "chaotic_cache",
		Gens:             3,
		Proto:            "tcp",
		SuccessThreshold: 1.0,
		Filters:          "--filter-tcp=443 --hostlist-domains=garudalinux.org,chaotic.cx",
		Targets: []types.Target{
			{URL: "https://builds.garudalinux.org/repos/chaotic-aur/x86_64/chaotic-aur.db.tar.zst", Threshold: 676248, IgnoreStatus: true, DownloadCheck: true, Proto: types.ProtoTCP, ID: "CHAOTIC-01"},
		},
	})
}
