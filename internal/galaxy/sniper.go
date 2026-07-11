package galaxy

import (
	"prikop/internal/evolution"
	"prikop/internal/model"
	"prikop/internal/nfqws2"
)

// GenerateZeroGeneration builds the initial nfqws2 population for a protocol.
//
// The v2 genome expresses every desync as an ordered list of lua-desync action
// instances (Strategy.Actions) behind a profile Filter, so the v1 "Mode"/option
// bag is gone: a v1 "fake,multisplit" directive becomes TWO ordered Actions.
// Blobs are the auto-initialized defaults (fake_default_tls / fake_default_quic)
// or inline 0xHEX; no /app/fake/*.bin file paths are referenced yet, which makes
// discoveredBins currently advisory only. Generation is fully deterministic.
func GenerateZeroGeneration(discoveredBins []string, report model.ReconReport, proto string) []nfqws2.Strategy {
	if proto == "udp" {
		pop := generateUDP()
		if report.BadSumWorks {
			// badsum-fooled QUIC fake: cheap corruption the DPI drops but the
			// server ignores, when the recon proved bad checksums survive NAT.
			pop = append(pop, udpStrat(fakeQUIC(
				nfqws2.P("repeats", "4"), nfqws2.Flag("badsum"),
			)))
		}
		return pop
	}

	var pop []nfqws2.Strategy
	// 1. Curated high-efficacy imports (the Yv series), translated to v2.
	pop = append(pop, generateImportedStrategies()...)
	// 2. SNI-independent structural archetypes.
	pop = append(pop, generateTCPStatic()...)
	// 3. SNI/host-bearing archetypes, one per common target.
	pop = append(pop, generateTCPPerTarget()...)
	// 4. Plain-HTTP profile archetypes.
	pop = append(pop, generateHTTP()...)

	if report.BadSumWorks {
		pop = append(pop,
			tcpStrat(fakeTLS("rnd,dupsid", nfqws2.P("repeats", "2"), nfqws2.Flag("badsum"))),
			tcpStrat(
				fakeTLS("rnd,dupsid", nfqws2.P("repeats", "2"), nfqws2.Flag("badsum")),
				split("multidisorder", "1,sniext"),
			),
		)
	}

	return pop
}

// ---- Profile filters -------------------------------------------------------

func tlsFilter() nfqws2.Filter {
	return nfqws2.Filter{TCP: "80,443", L7: []string{"tls"}, Payload: []string{"tls_client_hello"}}
}

func httpFilter() nfqws2.Filter {
	return nfqws2.Filter{TCP: "80", L7: []string{"http"}, Payload: []string{"http_req"}}
}

func quicFilter() nfqws2.Filter {
	return nfqws2.Filter{UDP: "443", L7: []string{"quic"}, Payload: []string{"quic_initial"}}
}

func tcpStrat(actions ...nfqws2.Action) nfqws2.Strategy {
	return nfqws2.Strategy{Filter: tlsFilter(), Actions: actions}
}

func httpStrat(actions ...nfqws2.Action) nfqws2.Strategy {
	return nfqws2.Strategy{Filter: httpFilter(), Actions: actions}
}

func udpStrat(actions ...nfqws2.Action) nfqws2.Strategy {
	return nfqws2.Strategy{Filter: quicFilter(), Actions: actions}
}

// ---- Action builders -------------------------------------------------------

// split builds a split/disorder-family action with a leading pos param.
func split(fn, pos string, extra ...nfqws2.Param) nfqws2.Action {
	ps := make([]nfqws2.Param, 0, 1+len(extra))
	if pos != "" {
		ps = append(ps, nfqws2.P("pos", pos))
	}
	ps = append(ps, extra...)
	return nfqws2.Action{Func: fn, Params: ps}
}

// fakeTLS builds a TCP fake action with the default TLS blob and optional mods.
func fakeTLS(tlsMod string, extra ...nfqws2.Param) nfqws2.Action {
	ps := make([]nfqws2.Param, 0, 2+len(extra))
	ps = append(ps, nfqws2.P("blob", nfqws2.BlobDefaultTLS))
	if tlsMod != "" {
		ps = append(ps, nfqws2.P("tls_mod", tlsMod))
	}
	ps = append(ps, extra...)
	return nfqws2.Action{Func: "fake", Params: ps}
}

// fakeQUIC builds a UDP fake action with the default QUIC blob.
func fakeQUIC(extra ...nfqws2.Param) nfqws2.Action {
	ps := make([]nfqws2.Param, 0, 1+len(extra))
	ps = append(ps, nfqws2.P("blob", nfqws2.BlobDefaultQUIC))
	ps = append(ps, extra...)
	return nfqws2.Action{Func: "fake", Params: ps}
}

// badseqData is the Linux-safe badack fooling for a data-phase packet:
// tcp_ack=-66000 plus the tcp_ts_up timestamp workaround (see mapping table).
func badseqData() []nfqws2.Param {
	return []nfqws2.Param{nfqws2.P("tcp_ack", "-66000"), nfqws2.Flag("tcp_ts_up")}
}

// ---- Curated imports (Yv series) ------------------------------------------

// generateImportedStrategies translates the hand-tuned v1 "Yv" strategies to v2.
// v1 foolings collapse into per-action params; a "fake,X" mode becomes an
// ordered [fake, X] action pair. Bin-file patterns are dropped (blob refinement
// is a later step), so every import is now unconditional.
func generateImportedStrategies() []nfqws2.Strategy {
	fakeMod := func(sni string, extra ...nfqws2.Param) nfqws2.Action {
		return fakeTLS("rnd,dupsid,sni="+sni, extra...)
	}

	return []nfqws2.Strategy{
		// Yv01
		tcpStrat(split("multisplit", "1", nfqws2.P("seqovl", "681"), nfqws2.P("ip_id", "zero"))),
		// Yv02
		tcpStrat(split("multisplit", "1,sniext+1", nfqws2.P("seqovl", "1"))),
		// Yv03
		tcpStrat(
			fakeMod("ggpht.com", append([]nfqws2.Param{nfqws2.Flag("badsum")}, badseqData()...)...),
			split("multisplit", "2,sld", nfqws2.P("seqovl", "620")),
		),
		// Yv04 (v1 split2 -> multisplit needs a pos)
		tcpStrat(split("multisplit", "1", nfqws2.P("seqovl", "681"))),
		// Yv05
		tcpStrat(
			nfqws2.Action{Func: "fake", Params: append([]nfqws2.Param{
				nfqws2.P("blob", "0x0F0F0F0F"), nfqws2.Flag("badsum"),
			}, badseqData()...)},
			split("fakeddisorder", "10,midsld", nfqws2.P("seqovl", "336")),
		),
		// Yv06
		tcpStrat(split("multidisorder", "7,sld+1",
			nfqws2.P("ip_autottl", "2,2-12"), nfqws2.P("ip6_autottl", "2,2-12"),
			nfqws2.P("tcp_ack", "-66000"), nfqws2.Flag("tcp_ts_up"),
		)),
		// Yv07
		tcpStrat(split("multidisorder", "1,midsld,endhost-1",
			nfqws2.P("repeats", "2"), nfqws2.Flag("tcp_md5"))),
		// Yv08
		tcpStrat(
			fakeMod("www.google.com", append([]nfqws2.Param{nfqws2.P("repeats", "2")}, badseqData()...)...),
			split("multisplit", "1,midsld"),
		),
		// Yv09
		tcpStrat(split("multidisorder", "1,midsld",
			nfqws2.P("repeats", "6"), nfqws2.P("tcp_ack", "-66000"), nfqws2.Flag("tcp_ts_up"))),
		// Yv10
		tcpStrat(split("multisplit", "1,2", nfqws2.P("seqovl", "4"))),
		// Yv11
		tcpStrat(split("multidisorder", "2,5,105,host+5,sld-1,endsld-5,endsld")),
		// Yv12
		tcpStrat(split("multidisorder", "1,midsld", nfqws2.P("repeats", "2"))),
		// Yv13
		tcpStrat(
			fakeMod("fonts.google.com", append([]nfqws2.Param{nfqws2.P("repeats", "2")}, badseqData()...)...),
			split("multidisorder", "1", nfqws2.P("seqovl", "681")),
		),
		// Yv14
		tcpStrat(
			fakeMod("fonts.google.com", badseqData()...),
			split("multidisorder", "10,midsld", nfqws2.P("seqovl", "336")),
		),
		// Yv15
		tcpStrat(
			fakeMod("ggpht.com", append([]nfqws2.Param{nfqws2.Flag("badsum")}, badseqData()...)...),
			split("multisplit", "2,sld", nfqws2.P("seqovl", "2108")),
		),
		// Yv16
		tcpStrat(split("multisplit", "1,sniext+1",
			nfqws2.P("seqovl", "1"), nfqws2.Flag("badsum"),
			nfqws2.P("tcp_ack", "-66000"), nfqws2.Flag("tcp_ts_up"))),
		// Yv17
		tcpStrat(split("fakeddisorder", "method+2", nfqws2.Flag("tcp_md5"))),
		// Yv18
		tcpStrat(
			fakeMod("www.google.com", nfqws2.Flag("tcp_ts_up"), nfqws2.P("ip_id", "zero")),
			nfqws2.Action{Func: "hostfakesplit", Params: []nfqws2.Param{
				nfqws2.P("host", "www.google.com"), nfqws2.P("altorder", "1"),
			}},
		),
		// Yv19
		tcpStrat(nfqws2.Action{Func: "hostfakesplit", Params: []nfqws2.Param{
			nfqws2.P("host", "google.com"), nfqws2.Flag("tcp_ts_up"),
		}}),
		// Yv20
		tcpStrat(
			fakeTLS("", nfqws2.P("repeats", "6"), nfqws2.Flag("tcp_ts_up"), nfqws2.P("ip_id", "zero")),
			split("fakedsplit", "1", nfqws2.P("pattern", "0x00")),
		),
		// Yv21
		tcpStrat(
			fakeTLS("", nfqws2.P("repeats", "8"), nfqws2.Flag("tcp_ts_up"), nfqws2.P("ip_id", "zero")),
			split("multisplit", "1", nfqws2.P("seqovl", "681")),
		),
	}
}

// ---- Procedural TCP --------------------------------------------------------

// generateTCPStatic emits SNI-independent structural archetypes exactly once.
func generateTCPStatic() []nfqws2.Strategy {
	return []nfqws2.Strategy{
		tcpStrat(split("multisplit", "1")),
		tcpStrat(split("multisplit", "1,midsld")),
		tcpStrat(split("multisplit", "sniext+1")),
		tcpStrat(split("multidisorder", "1,midsld", nfqws2.P("repeats", "2"))),
		tcpStrat(split("fakedsplit", "1", nfqws2.P("pattern", "0x00"))),
		tcpStrat(split("fakeddisorder", "10,midsld", nfqws2.P("seqovl", "336"), nfqws2.P("pattern", "0x00"))),
		tcpStrat(split("tcpseg", "1,midsld")),
	}
}

// generateTCPPerTarget emits SNI/host-bearing archetypes, one per common target.
func generateTCPPerTarget() []nfqws2.Strategy {
	var out []nfqws2.Strategy
	for _, sni := range evolution.CommonSNIs {
		tlsMod := "rnd,dupsid,sni=" + sni
		// fake + multisplit
		out = append(out, tcpStrat(
			fakeTLS(tlsMod, nfqws2.P("repeats", "2")),
			split("multisplit", "2,sld", nfqws2.P("seqovl", "620")),
		))
		// fake + multidisorder
		out = append(out, tcpStrat(
			fakeTLS(tlsMod, nfqws2.P("repeats", "2")),
			split("multidisorder", "1,midsld"),
		))
	}
	// hostfakesplit: masked host header, one per common host.
	for i, host := range evolution.CommonHosts {
		sni := evolution.CommonSNIs[i%len(evolution.CommonSNIs)]
		out = append(out, tcpStrat(
			fakeTLS("rnd,dupsid,sni="+sni, nfqws2.Flag("tcp_ts_up"), nfqws2.P("ip_id", "zero")),
			nfqws2.Action{Func: "hostfakesplit", Params: []nfqws2.Param{nfqws2.P("host", host)}},
		))
	}
	return out
}

// generateHTTP emits plain-HTTP profile archetypes.
func generateHTTP() []nfqws2.Strategy {
	return []nfqws2.Strategy{
		httpStrat(split("multisplit", "method+2")),
		httpStrat(split("multidisorder", "method+2", nfqws2.P("repeats", "2"))),
		httpStrat(nfqws2.Action{Func: "http_hostcase"}),
		httpStrat(nfqws2.Action{Func: "http_domcase"}),
	}
}

// ---- Procedural UDP --------------------------------------------------------

// generateUDP emits the QUIC/UDP archetypes: quic-blob fakes and udplen.
func generateUDP() []nfqws2.Strategy {
	return []nfqws2.Strategy{
		udpStrat(fakeQUIC(nfqws2.P("repeats", "4"))),
		udpStrat(fakeQUIC(nfqws2.P("repeats", "6"), nfqws2.P("ip_ttl", "3"))),
		udpStrat(nfqws2.Action{Func: "udplen", Params: []nfqws2.Param{nfqws2.P("inc", "2")}}),
		udpStrat(
			fakeQUIC(nfqws2.P("repeats", "5")),
			nfqws2.Action{Func: "udplen", Params: []nfqws2.Param{nfqws2.P("inc", "2")}},
		),
	}
}
