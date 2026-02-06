package targets

import (
	"prikop/internal/model"
	"strings"
)

func GetList() []model.Target {
	return append(getBinaries(), getGeneralBlocking()...)
}

func GetGroup(name string) []model.Target {
	all := GetList()
	var filtered []model.Target

	// Helper to split name like "google_tcp" -> "google", "tcp"
	baseName := name
	protoFilter := "" // "" = all, "tcp", "udp" (quic is udp)

	if strings.HasSuffix(name, "_tcp") {
		baseName = strings.TrimSuffix(name, "_tcp")
		protoFilter = "tcp"
	} else if strings.HasSuffix(name, "_udp") {
		baseName = strings.TrimSuffix(name, "_udp")
		protoFilter = "udp"
	}

	for _, t := range all {
		// 1. Filter by Provider/ID
		match := false
		switch baseName {
		case "google":
			if isGoogle(t) {
				match = true
			}
		case "discord":
			if isDiscord(t) {
				match = true
			}
		case "general":
			if !isGoogle(t) && !isDiscord(t) {
				match = true
			}
		default:
			// "all" or unknown
			match = true
		}

		if !match {
			continue
		}

		// 2. Filter by Protocol
		if protoFilter == "tcp" {
			// Target is TCP if Proto is empty or "tcp"
			if t.Proto != "" && t.Proto != "tcp" {
				continue
			}
		} else if protoFilter == "udp" {
			// Target is UDP/QUIC if Proto is "quic" or "udp"
			if t.Proto != "quic" && t.Proto != "udp" {
				continue
			}
		}

		filtered = append(filtered, t)
	}
	return filtered
}

func isGoogle(t model.Target) bool {
	id := strings.ToUpper(t.ID)
	prov := strings.ToUpper(t.Provider)
	return strings.Contains(id, "YT") || strings.Contains(id, "GC") ||
		strings.Contains(prov, "GOOGLE") || strings.Contains(prov, "YOUTUBE")
}

func isDiscord(t model.Target) bool {
	id := strings.ToUpper(t.ID)
	prov := strings.ToUpper(t.Provider)
	return strings.Contains(id, "DSC") || strings.Contains(prov, "DISCORD")
}

func getBinaries() []model.Target {
	return []model.Target{
		{ID: "US.CF-01", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://img.wzstats.gg/cleaver/gunFullDisplay", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.CF-02", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://genshin.jmp.blue/characters/all#", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.CF-03", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.CF-04", Provider: "🇨🇦 Cloudflare", Times: 1, URL: "https://www.bigcartel.com/", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.DO-01", Provider: "🇺🇸 DigitalOcean", Times: 2, URL: "https://genderize.io/", Threshold: model.DefaultBinaryThreshold},
		{ID: "DE.HE-01", Provider: "🇩🇪 Hetzner", Times: 1, URL: "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp", Threshold: model.DefaultBinaryThreshold},
		{ID: "DE.HE-02", Provider: "🇩🇪 Hetzner", Times: 1, URL: "https://accesorioscelular.com/tienda/css/plugins.css", Threshold: model.DefaultBinaryThreshold},
		{ID: "FI.HE-01", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://251b5cd9.nip.io/1MB.bin", Threshold: model.DefaultBinaryThreshold},
		{ID: "FI.HE-02", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://nioges.com/libs/fontawesome/webfonts/fa-solid-900.woff2", Threshold: model.DefaultBinaryThreshold},
		{ID: "FI.HE-03", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://5fd8bdae.nip.io/1MB.bin", Threshold: model.DefaultBinaryThreshold},
		{ID: "FI.HE-04", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://5fd8bca5.nip.io/1MB.bin", Threshold: model.DefaultBinaryThreshold},
		{ID: "FR.OVH-01", Provider: "🇫🇷 OVH", Times: 1, URL: "https://eu.api.ovh.com/console/rapidoc-min.js", Threshold: model.DefaultBinaryThreshold},
		{ID: "FR.OVH-02", Provider: "🇫🇷 OVH", Times: 1, URL: "https://ovh.sfx.ovh/10M.bin", Threshold: model.DefaultBinaryThreshold},
		{ID: "SE.OR-01", Provider: "🇸🇪 Oracle", Times: 1, URL: "https://oracle.sfx.ovh/10M.bin", Threshold: model.DefaultBinaryThreshold},
		{ID: "DE.AWS-01", Provider: "🇩🇪 AWS", Times: 1, URL: "https://www.getscope.com/assets/fonts/fa-solid-900.woff2", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.AWS-01", Provider: "🇺🇸 AWS", Times: 1, URL: "https://corp.kaltura.com/wp-content/cache/min/1/wp-content/themes/airfleet/dist/styles/theme.css", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.GC-01", Provider: "🇺🇸 Google Cloud", Times: 1, URL: "https://api.usercentrics.eu/gvl/v3/en.json", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.FST-01", Provider: "🇺🇸 Fastly", Times: 1, URL: "https://www.jetblue.com/footer/footer-element-es2015.js", Threshold: model.DefaultBinaryThreshold},
		{ID: "CA.FST-01", Provider: "🇨🇦 Fastly", Times: 1, URL: "https://ssl.p.jwpcdn.com/player/v/8.40.5/bidding.js", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.AKM-01", Provider: "🇺🇸 Akamai", Times: 1, URL: "https://www.roxio.com/static/roxio/images/products/creator/nxt9/call-action-footer-bg.jpg", Threshold: model.DefaultBinaryThreshold},
		{ID: "PL.AKM-01", Provider: "🇵🇱 Akamai", Times: 1, URL: "https://media-assets.stryker.com/is/image/stryker/gateway_1?$max_width_1410$", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.CDN77-01", Provider: "🇺🇸 CDN77", Times: 1, URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg", Threshold: model.DefaultBinaryThreshold},
		{ID: "FR.CNTB-01", Provider: "🇫🇷 Contabo", Times: 1, URL: "https://xdmarineshop.gr/index.php?route=index", Threshold: model.DefaultBinaryThreshold},
		{ID: "NL.SW-01", Provider: "🇳🇱 Scaleway", Times: 1, URL: "https://www.velivole.fr/img/header.jpg", Threshold: model.DefaultBinaryThreshold},
		{ID: "US.CNST-01", Provider: "🇺🇸 Constant", Times: 1, URL: "https://cdn.xuansiwei.com/common/lib/font-awesome/4.7.0/fontawesome-webfont.woff2?v=4.7.0", Threshold: model.DefaultBinaryThreshold},
	}
}

func getGeneralBlocking() []model.Target {
	return []model.Target{
		// RU GOV
		{ID: "RU.GOV-01", Provider: "🇷🇺 Govt", Times: 1, URL: "https://gosuslugi.ru", Threshold: model.DefaultWebThreshold},
		{ID: "RU.GOV-02", Provider: "🇷🇺 Govt", Times: 1, URL: "https://esia.gosuslugi.ru", Threshold: model.DefaultWebThreshold},
		{ID: "RU.GOV-03", Provider: "🇷🇺 Govt", Times: 1, URL: "https://nalog.ru", Threshold: model.DefaultWebThreshold},
		// SOCIALS
		{ID: "US.META-01", Provider: "🇺🇸 Meta", Times: 1, URL: "https://instagram.com", Threshold: model.DefaultWebThreshold},
		{ID: "US.META-02", Provider: "🇺🇸 Meta", Times: 1, URL: "https://facebook.com", Threshold: model.DefaultWebThreshold},
		{ID: "US.X-01", Provider: "🇺🇸 X", Times: 1, URL: "https://x.com", Threshold: model.DefaultWebThreshold},

		// DISCORD (Expanded)
		{ID: "US.DSC-API", Provider: "🇺🇸 Discord", Times: 1, URL: "https://discord.com", Threshold: model.DefaultWebThreshold},
		{ID: "US.DSC-CDN", Provider: "🇺🇸 Discord", Times: 1, URL: "https://cdn.discordapp.com", Threshold: model.DefaultWebThreshold},
		{ID: "US.DSC-GG", Provider: "🇺🇸 Discord", Times: 1, URL: "https://discord.gg", Threshold: model.DefaultWebThreshold},
		{ID: "US.DSC-NET", Provider: "🇺🇸 Discord", Times: 1, URL: "https://discordapp.net", Threshold: model.DefaultWebThreshold},

		// VIDEO (TCP)
		{ID: "RU.RT-01", Provider: "🇷🇺 Rutube", Times: 1, URL: "https://rutube.ru", Threshold: model.DefaultWebThreshold},
		{ID: "US.YT-01", Provider: "🇺🇸 YouTube GGC", Times: 1, URL: "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com", Threshold: model.DefaultWebThreshold, IgnoreStatus: true},
		{ID: "US.YT-02", Provider: "🇺🇸 YouTube", Times: 1, URL: "https://googlevideo.com", Threshold: model.DefaultWebThreshold, IgnoreStatus: true},

		// VIDEO (QUIC/HTTP3)
		{ID: "US.YT-Q01", Provider: "🇺🇸 YouTube QUIC", Times: 1, URL: "https://googlevideo.com", Threshold: model.DefaultWebThreshold, Proto: "quic", IgnoreStatus: true},
		{ID: "US.YT-Q02", Provider: "🇺🇸 YouTube QUIC", Times: 1, URL: "https://www.youtube.com", Threshold: model.DefaultWebThreshold, Proto: "quic"},

		// TORRENTS / COMMUNITY
		{ID: "RU.NTC-01", Provider: "🌐 NTC", Times: 1, URL: "https://ntc.party", Threshold: model.DefaultWebThreshold},
		{ID: "RU.TR-01", Provider: "🏴‍☠️ Rutor", Times: 1, URL: "https://rutor.info", Threshold: model.DefaultWebThreshold},
		{ID: "RU.TR-02", Provider: "🏴‍☠️ Rutracker", Times: 1, URL: "https://rutracker.org", Threshold: model.DefaultWebThreshold},
		{ID: "RU.TR-03", Provider: "🏴‍☠️ NNM", Times: 1, URL: "https://nnmclub.to", Threshold: model.DefaultWebThreshold},
		// ADULT
		{ID: "US.PH-01", Provider: "🇺🇸 PH", Times: 1, URL: "https://pornhub.com", Threshold: model.DefaultWebThreshold},
		{ID: "US.SB-01", Provider: "🇺🇸 SB", Times: 1, URL: "https://ru.spankbang.com", Threshold: model.DefaultWebThreshold},
	}
}
