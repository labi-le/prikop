package availability

import "prikop/internal/verifier/types"

// cache.nixos.org is the NixOS binary cache (Fastly-fronted HTTPS). Russian DPI
// throttles/resets these transfers, so a NixOS box can't fetch packages. We
// test a REAL, content-addressed nar — the exact object Nix pulls during a
// build — so evolution optimizes for real package delivery, not the cache root.
//
// The URL + size are pulled from the package's real .narinfo metadata, the same
// "fetch real data, don't hardcode fakes" approach as generate-tcp16_20:
//
//	h=$(realpath "$(command -v bash)" | cut -d/ -f4 | cut -d- -f1)
//	curl https://cache.nixos.org/$h.narinfo
//	  URL:      nar/<narhash>.nar.zst  -> the real download link (*narhash)
//	  FileSize: 1638786                -> bytes on the wire  (Threshold)
//	  NarSize:  7415800                -> uncompressed size
//
// Target: bash-interactive-5.3p9. nars are content-addressed, so this object is
// permanent (Nix reproducibility) — safe to pin. The checker HEADs then POSTs
// 64 KiB with SNI=cache.nixos.org; Fastly 405s the POST but the bytes still
// cross the DPI, so it cleanly measures SNI/connection-level blocking.
func init() {
	registerProvider(types.ProviderDefinition{
		Name:             "nixos_cache",
		Gens:             3,
		Proto:            "tcp",
		SuccessThreshold: 1.0,
		Filters:          "--filter-tcp=443 --hostlist-domains=cache.nixos.org",
		Targets: []types.Target{
			{URL: "https://cache.nixos.org/nar/0cr6df6dl4y8sp6nmnmpfhhzbqrnawm504sszisfxh1yi05jhigb.nar.zst", Threshold: 1638786, IgnoreStatus: true, DownloadCheck: true, Proto: types.ProtoTCP, ID: "NIX-01"},
		},
	})
}
