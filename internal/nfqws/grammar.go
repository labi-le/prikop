package nfqws

/*
ZAPRET STRATEGY FLAGS DOCUMENTATION

This file defines the flags used by nfqws (and dvtws) for DPI circumvention.
Below is a detailed description of the flags, their constraints, and technical nuances.

GENERAL PRINCIPLES:
- nfqws is a packet modifier and NFQUEUE handler.
- It targets preventing ban triggers from firing rather than eliminating consequences.
- Techniques involve sending unexpected data to DPI (segmentation, fakes, fragmentation).

DPI DESYNC ATTACKS (--dpi-desync):
Combines multiple modes (up to 3) in ascending phase order:
Phase 0: Connection establishment (synack, syndata, --wssize).
Phase 1: Fakes before original data (fake, rst, rstack).
Phase 2: Modified original data (fakedsplit, ipfrag2, multisplit, multidisorder).

FAKES FOOLING (--dpi-desync-fooling):
- md5sig: Usually works only on Linux servers. Adds TCP option, can cause MTU overflow.
- badsum: Fails if behind NAT that verifies checksums (e.g., net.netfilter.nf_conntrack_checksum=1).
- badseq: Dropped by server. Default increment is -10000. Use 0x80000000 to ensure it's outside window.
- TTL: Requires tuning per ISP. Risk of cutting access to local ISP sites if set too low.
- hopbyhop/hopbyhop2: IPv6 only. hopbyhop2 violates RFC; most OS discard it.
- datanoack: Sends TCP fakes without ACK flag. Breaks NAT/masquerade; requires external IP.
- ts: Adds timestamp increment (-600000 default). Requires timestamps enabled in OS.
- autottl: Guesses hop count to server. Requires redirecting the first incoming packet (SYN,ACK).

TCP SEGMENTATION & DISORDER:
- multisplit: Splits at specified positions (--dpi-desync-split-pos).
- multidisorder: Sends segments in reverse order.
- fakedsplit/fakeddisorder: Single position split with fake mix.
- hostfakesplit: Fakes the hostname part (TLS/HTTP).
- seqovl: Sequence number overlap. Works on most Unix OS; fails on Windows servers in disorder mode.

WSS (Window Size Scaling) (--wssize):
- Forces server to split replies (e.g., ServerHello).
- Default scale factor is 0. Recommended: 1:6 (forces split TLS certificate).
- Use --wssize-cutoff to stop scaling after request to maintain speed.

IP_ID ASSIGNMENT (--ip-id):
- seq: Increment per packet.
- seqgroup: Same IP_ID for fake replacements.
- rnd: Random IP_ID.
- zero: Zeroed IP_ID (Linux/BSD sends zero, Windows replaces with counter).

IPV6 SPECIFIC:
- hopbyhop, destopt, ipfrag1: Adds extension headers to desync DPI.
- Headers increase packet size; may fail on max-sized packets.

UDP SUPPORT:
- Limited to: fake, fakeknown, hopbyhop, destopt, ipfrag1, ipfrag2, udplen, tamper.
- udplen: Increases payload size to resist size-tracking DPI.
- QUIC/Wireguard/DHT/STUN/Discord discovery recognition is supported.

IP FRAGMENTATION:
- Often filtered by networks or reassembled by middleboxes.
- IPv4: Standard firewall rules in OUTPUT chain might cause raw send to fail.
- IPv6: Linux often defragments automatically; requires nftables with priority -450 or raw_before_defrag=1.

CONSTRAINTS & CAVEATS:
- Virtual Machines: NAT mode in VirtualBox/VMware often breaks TTL magic and fakes. Use Bridge mode.
- Flow Offloading: Hardware/Software offloading bypasses Netfilter. Must be disabled or selectively controlled.
- Conntrack: nfqws needs to see the full connection lifecycle for stateful attacks.
- Reassemble: Supports multi-packet TLS/QUIC ClientHello (e.g., Chrome Kyber).
*/

import (
	"fmt"
	"strings"
)

// Strategy describes the nfqws arguments genome
type Strategy struct {
	Mode        string
	Repeats     int
	AnyProtocol bool
	SkipNoSNI   bool
	Cutoff      string
	Start       string
	FwMark      string

	Fooling  FoolingSet
	Fake     FakeOptions
	Split    SplitOptions
	TTL      TTLOptions
	WSS      WSSOptions
	UdpLen   UdpLenOptions
	Tamper   TamperOptions
	Dup      DupOptions
	Orig     OrigOptions
	TcpFlags TcpFlagsOptions
}

type FoolingSet struct {
	Md5Sig          bool
	BadSum          bool
	BadSeq          bool
	Ts              bool
	Datanoack       bool
	HopByHop        bool
	HopByHop2       bool
	BadSeqIncrement int
	BadAckIncrement int
	TsIncrement     int
}

type FakeOptions struct {
	TLS        string
	Quic       string
	Http       string
	Wireguard  string
	Dht        string
	Discord    string
	Stun       string
	UnknownUdp string
	Unknown    string
	SynData    string
	TlsMod     string
	TcpMod     string
}

type SplitOptions struct {
	Pos     string
	SeqOvl  int
	Pattern string

	FakedPattern string
	FakedMod     string

	HostMid string
	HostMod string

	IpFragPosTcp int
	IpFragPosUdp int
}

type UdpLenOptions struct {
	Increment int
	Pattern   string
}

type TTLOptions struct {
	Fixed   int
	Fixed6  int
	Auto    int
	Auto6   int
	AutoStr string
}

type WSSOptions struct {
	Enabled      bool
	Value        string
	Cutoff       string
	ForcedCutoff bool
}

type TamperOptions struct {
	HostCase    bool
	HostSpell   string
	HostNoSpace bool
	DomCase     bool
	MethodEol   bool
	IpId        string
	SynAckSplit string
}

type DupOptions struct {
	Count           int
	Replace         bool
	TTL             int
	TTL6            int
	AutoTTL         string
	AutoTTL6        string
	Fooling         string
	TsIncrement     int
	BadSeqIncrement int
	BadAckIncrement int
	IpId            string
	Start           string
	Cutoff          string
	TcpFlagsSet     string
	TcpFlagsUnset   string
}

type OrigOptions struct {
	TTL           int
	TTL6          int
	AutoTTL       string
	AutoTTL6      string
	TcpFlagsSet   string
	TcpFlagsUnset string
	ModStart      string
	ModCutoff     string
}

type TcpFlagsOptions struct {
	Set   string
	Unset string
}

const (
	// ArgDpiDesync: Primary desync mode. Modes: synack, fake, fakeknown, rst, rstack, hopbyhop, destopt, ipfrag1, multisplit, multidisorder, fakedsplit, hostfakesplit, fakeddisorder, ipfrag2, udplen, tamper.
	ArgDpiDesync               = "--dpi-desync"
	// ArgDpiDesyncRepeats: Number of times to resend each desync packet.
	ArgDpiDesyncRepeats        = "--dpi-desync-repeats"
	// ArgDpiDesyncAnyProtocol: If 1, desync any nonempty data packet, not just HTTP/TLS.
	ArgDpiDesyncAnyProtocol    = "--dpi-desync-any-protocol"
	// ArgDpiDesyncSkipNoSNI: If 1 (default), do not act on ClientHello without SNI.
	ArgDpiDesyncSkipNoSNI      = "--dpi-desync-skip-nosni"
	// ArgDpiDesyncCutoff: Stop desync after N packets (n), data packets (d), or relative sequence (s).
	ArgDpiDesyncCutoff         = "--dpi-desync-cutoff"
	// ArgDpiDesyncStart: Start desync after N packets (n), data packets (d), or relative sequence (s).
	ArgDpiDesyncStart          = "--dpi-desync-start"
	// ArgDpiDesyncFwmark: Override fwmark for desync packets (default 0x40000000).
	ArgDpiDesyncFwmark         = "--dpi-desync-fwmark"
	// ArgDpiDesyncFooling: Comma-separated fooling modes: none, md5sig, ts, badseq, badsum, datanoack, hopbyhop, hopbyhop2.
	ArgDpiDesyncFooling        = "--dpi-desync-fooling"
	// ArgDpiDesyncBadSeqInc: Seq increment for badseq fooling (default -10000).
	ArgDpiDesyncBadSeqInc      = "--dpi-desync-badseq-increment"
	// ArgDpiDesyncBadAckInc: Ack increment for badseq fooling (default -66000).
	ArgDpiDesyncBadAckInc      = "--dpi-desync-badack-increment"
	// ArgDpiDesyncTsInc: TSVal increment for ts fooling (default -600000).
	ArgDpiDesyncTsInc          = "--dpi-desync-ts-increment"
	// ArgDpiDesyncFakeTls: File path or hex for custom TLS ClientHello fake.
	ArgDpiDesyncFakeTls        = "--dpi-desync-fake-tls"
	// ArgDpiDesyncFakeQuic: File path or hex for custom QUIC Initial fake.
	ArgDpiDesyncFakeQuic       = "--dpi-desync-fake-quic"
	// ArgDpiDesyncFakeHttp: File path or hex for custom HTTP request fake.
	ArgDpiDesyncFakeHttp       = "--dpi-desync-fake-http"
	// ArgDpiDesyncFakeWireguard: File path or hex for custom Wireguard handshake fake.
	ArgDpiDesyncFakeWireguard  = "--dpi-desync-fake-wireguard"
	// ArgDpiDesyncFakeDht: File path or hex for custom DHT fake.
	ArgDpiDesyncFakeDht        = "--dpi-desync-fake-dht"
	// ArgDpiDesyncFakeDiscord: File path or hex for custom Discord IP Discovery fake.
	ArgDpiDesyncFakeDiscord    = "--dpi-desync-fake-discord"
	// ArgDpiDesyncFakeStun: File path or hex for custom STUN fake.
	ArgDpiDesyncFakeStun       = "--dpi-desync-fake-stun"
	// ArgDpiDesyncFakeUnknownUdp: File path or hex for unknown UDP protocol fake.
	ArgDpiDesyncFakeUnknownUdp = "--dpi-desync-fake-unknown-udp"
	// ArgDpiDesyncFakeUnknown: File path or hex for unknown TCP protocol fake.
	ArgDpiDesyncFakeUnknown    = "--dpi-desync-fake-unknown"
	// ArgDpiDesyncFakeSynData: File path or hex for SYN data payload.
	ArgDpiDesyncFakeSynData    = "--dpi-desync-fake-syndata"
	// ArgDpiDesyncFakeTlsMod: Runtime TLS fake mods: none, rnd, rndsni, sni=<sni>, dupsid, padencap.
	ArgDpiDesyncFakeTlsMod     = "--dpi-desync-fake-tls-mod"
	// ArgDpiDesyncFakeTcpMod: TCP fake mods: none, seq. 'seq' treats fakes as segments of one stream.
	ArgDpiDesyncFakeTcpMod     = "--dpi-desync-fake-tcp-mod"
	// ArgDpiDesyncSplitPos: Comma-separated split positions. Markers: method, host, endhost, sld, endsld, midsld, sniext.
	ArgDpiDesyncSplitPos       = "--dpi-desync-split-pos"
	// ArgDpiDesyncSplitSeqOvl: Use sequence overlap before first split segment.
	ArgDpiDesyncSplitSeqOvl    = "--dpi-desync-split-seqovl"
	// ArgDpiDesyncSplitPattern: Pattern for fake part of sequence overlap.
	ArgDpiDesyncSplitPattern   = "--dpi-desync-split-seqovl-pattern"
	// ArgDpiDesyncFakedPattern: Fake pattern for fakedsplit/fakeddisorder.
	ArgDpiDesyncFakedPattern   = "--dpi-desync-fakedsplit-pattern"
	// ArgDpiDesyncFakedMod: Mods for fakedsplit/fakeddisorder (altorder=N).
	ArgDpiDesyncFakedMod       = "--dpi-desync-fakedsplit-mod"
	// ArgDpiDesyncHostFakeMid: Additionally split real hostname at marker (within host..endhost).
	ArgDpiDesyncHostFakeMid    = "--dpi-desync-hostfakesplit-midhost"
	// ArgDpiDesyncHostFakeMod: hostfakesplit mods: none, host=<hostname>, altorder=0|1.
	ArgDpiDesyncHostFakeMod    = "--dpi-desync-hostfakesplit-mod"
	// ArgDpiDesyncIpFragPosTcp: IPv4 fragment position for TCP (multiple of 8, default 32).
	ArgDpiDesyncIpFragPosTcp   = "--dpi-desync-ipfrag-pos-tcp"
	// ArgDpiDesyncIpFragPosUdp: IPv4 fragment position for UDP (multiple of 8, default 8).
	ArgDpiDesyncIpFragPosUdp   = "--dpi-desync-ipfrag-pos-udp"
	// ArgDpiDesyncUdpLenInc: Increase/decrease UDP packet length by N bytes.
	ArgDpiDesyncUdpLenInc      = "--dpi-desync-udplen-increment"
	// ArgDpiDesyncUdpLenPattern: Tail fill pattern for udplen.
	ArgDpiDesyncUdpLenPattern  = "--dpi-desync-udplen-pattern"
	// ArgDpiDesyncTTL: Set fixed TTL for desync packets.
	ArgDpiDesyncTTL            = "--dpi-desync-ttl"
	// ArgDpiDesyncTTL6: Set fixed Hop Limit for IPv6 desync packets.
	ArgDpiDesyncTTL6           = "--dpi-desync-ttl6"
	// ArgDpiDesyncAutoTTL: Auto TTL mode: delta[:min[-max]]. Default -1:3-20.
	ArgDpiDesyncAutoTTL        = "--dpi-desync-autottl"
	// ArgDpiDesyncAutoTTL6: Overrides ArgDpiDesyncAutoTTL for IPv6.
	ArgDpiDesyncAutoTTL6       = "--dpi-desync-autottl6"
	// ArgDpiDesyncTcpFlagsSet: Set specific TCP flags in desync packets.
	ArgDpiDesyncTcpFlagsSet    = "--dpi-desync-tcp-flags-set"
	// ArgDpiDesyncTcpFlagsUnset: Unset specific TCP flags in desync packets.
	ArgDpiDesyncTcpFlagsUnset  = "--dpi-desync-tcp-flags-unset"
	// ArgWSSize: Set TCP window size and scale factor for server (e.g., 1:6).
	ArgWSSize                  = "--wssize"
	// ArgWSSizeCutoff: Threshold to stop applying wssize (n, d, s).
	ArgWSSizeCutoff            = "--wssize-cutoff"
	// ArgWSSizeForcedCutoff: If 1 (default), auto cutoff wssize on known protocol.
	ArgWSSizeForcedCutoff      = "--wssize-forced-cutoff"
	// ArgHostCase: Change Host: => host: in HTTP.
	ArgHostCase                = "--hostcase"
	// ArgHostSpell: Exact spelling of "Host" header (4 chars).
	ArgHostSpell               = "--hostspell"
	// ArgHostNoSpace: Remove space after Host: header.
	ArgHostNoSpace             = "--hostnospace"
	// ArgDomCase: Mix case of domain name in Host header.
	ArgDomCase                 = "--domcase"
	// ArgMethodEol: Add \n before HTTP method.
	ArgMethodEol               = "--methodeol"
	// ArgIpId: IPv4 IP_ID assignment: zero, seq, seqgroup, rnd.
	ArgIpId                    = "--ip-id"
	// ArgSynAckSplit: Perform TCP split handshake: syn, synack, acksyn.
	ArgSynAckSplit             = "--synack-split"
	// ArgDup: Duplicate original packets N times.
	ArgDup                     = "--dup"
	// ArgDupReplace: If 1, do not send original packet, only dups.
	ArgDupReplace              = "--dup-replace"
	// ArgDupTTL: TTL for duplicated packets.
	ArgDupTTL                  = "--dup-ttl"
	// ArgDupTTL6: Hop Limit for IPv6 duplicated packets.
	ArgDupTTL6                 = "--dup-ttl6"
	// ArgDupAutoTTL: Auto TTL mode for duplicates.
	ArgDupAutoTTL              = "--dup-autottl"
	// ArgDupAutoTTL6: Overrides ArgDupAutoTTL for IPv6.
	ArgDupAutoTTL6             = "--dup-autottl6"
	// ArgDupFooling: Fooling modes for duplicates.
	ArgDupFooling              = "--dup-fooling"
	// ArgDupTsInc: TSVal increment for duplicates.
	ArgDupTsInc                = "--dup-ts-increment"
	// ArgDupBadSeqInc: Seq increment for duplicates.
	ArgDupBadSeqInc            = "--dup-badseq-increment"
	// ArgDupBadAckInc: Ack increment for duplicates.
	ArgDupBadAckInc            = "--dup-badack-increment"
	// ArgDupIpId: IP_ID mode for duplicates.
	ArgDupIpId                 = "--dup-ip-id"
	// ArgDupStart: Start duplicating after N packets.
	ArgDupStart                = "--dup-start"
	// ArgDupCutoff: Stop duplicating after N packets.
	ArgDupCutoff               = "--dup-cutoff"
	// ArgDupTcpFlagsSet: Set TCP flags for duplicates.
	ArgDupTcpFlagsSet          = "--dup-tcp-flags-set"
	// ArgDupTcpFlagsUnset: Unset TCP flags for duplicates.
	ArgDupTcpFlagsUnset        = "--dup-tcp-flags-unset"
	// ArgOrigTTL: Set TTL for original packets.
	ArgOrigTTL                 = "--orig-ttl"
	// ArgOrigTTL6: Set Hop Limit for IPv6 original packets.
	ArgOrigTTL6                = "--orig-ttl6"
	// ArgOrigAutoTTL: Auto TTL mode for original packets.
	ArgOrigAutoTTL             = "--orig-autottl"
	// ArgOrigAutoTTL6: Overrides ArgOrigAutoTTL for IPv6.
	ArgOrigAutoTTL6            = "--orig-autottl6"
	// ArgOrigModStart: Start modding original packets after N packets.
	ArgOrigModStart            = "--orig-mod-start"
	// ArgOrigModCutoff: Stop modding original packets after N packets.
	ArgOrigModCutoff           = "--orig-mod-cutoff"
	// ArgOrigTcpFlagsSet: Set TCP flags for original packets.
	ArgOrigTcpFlagsSet         = "--orig-tcp-flags-set"
	// ArgOrigTcpFlagsUnset: Unset TCP flags for original packets.
	ArgOrigTcpFlagsUnset       = "--orig-tcp-flags-unset"
)

func (s Strategy) String() string {
	return strings.Join(s.ToArgs(), " ")
}

func (s Strategy) ToArgs() []string {
	var args []string
	args = append(args, s.argsMain()...)
	args = append(args, s.argsFooling()...)
	args = append(args, s.argsFake()...)
	args = append(args, s.argsSplit()...)
	args = append(args, s.argsUdpLen()...)
	args = append(args, s.argsTTL()...)
	args = append(args, s.argsTcpFlags()...)
	args = append(args, s.argsWSS()...)
	args = append(args, s.argsTamper()...)
	args = append(args, s.argsDup()...)
	args = append(args, s.argsOrig()...)

	return args
}

func addArg(args []string, flag, value string) []string {
	if value != "" {
		return append(args, fmt.Sprintf("%s=%s", flag, value))
	}
	return args
}

func addArgInt(args []string, flag string, value int) []string {
	if value != 0 {
		return append(args, fmt.Sprintf("%s=%d", flag, value))
	}
	return args
}

func (s Strategy) argsMain() []string {
	var args []string
	args = addArg(args, ArgDpiDesync, s.Mode)
	if s.Repeats > 1 {
		args = append(args, fmt.Sprintf("%s=%d", ArgDpiDesyncRepeats, s.Repeats))
	}
	if s.AnyProtocol {
		args = append(args, ArgDpiDesyncAnyProtocol+"=1")
	}
	if s.SkipNoSNI {
		args = append(args, ArgDpiDesyncSkipNoSNI+"=1")
	}
	args = addArg(args, ArgDpiDesyncCutoff, s.Cutoff)
	args = addArg(args, ArgDpiDesyncStart, s.Start)
	args = addArg(args, ArgDpiDesyncFwmark, s.FwMark)
	return args
}

func (s Strategy) argsFooling() []string {
	var args []string
	var flags []string
	f := s.Fooling
	if f.Md5Sig {
		flags = append(flags, "md5sig")
	}
	if f.BadSum {
		flags = append(flags, "badsum")
	}
	if f.BadSeq {
		flags = append(flags, "badseq")
	}
	if f.Ts {
		flags = append(flags, "ts")
	}
	if f.Datanoack {
		flags = append(flags, "datanoack")
	}
	if f.HopByHop {
		flags = append(flags, "hopbyhop")
	}
	if f.HopByHop2 {
		flags = append(flags, "hopbyhop2")
	}
	if len(flags) > 0 {
		args = append(args, fmt.Sprintf("%s=%s", ArgDpiDesyncFooling, strings.Join(flags, ",")))
	}
	args = addArgInt(args, ArgDpiDesyncBadSeqInc, f.BadSeqIncrement)
	args = addArgInt(args, ArgDpiDesyncBadAckInc, f.BadAckIncrement)
	args = addArgInt(args, ArgDpiDesyncTsInc, f.TsIncrement)
	return args
}

func (s Strategy) argsFake() []string {
	var args []string
	f := s.Fake
	args = addArg(args, ArgDpiDesyncFakeTls, f.TLS)
	args = addArg(args, ArgDpiDesyncFakeQuic, f.Quic)
	args = addArg(args, ArgDpiDesyncFakeHttp, f.Http)
	args = addArg(args, ArgDpiDesyncFakeWireguard, f.Wireguard)
	args = addArg(args, ArgDpiDesyncFakeDht, f.Dht)
	args = addArg(args, ArgDpiDesyncFakeDiscord, f.Discord)
	args = addArg(args, ArgDpiDesyncFakeStun, f.Stun)
	args = addArg(args, ArgDpiDesyncFakeUnknownUdp, f.UnknownUdp)
	args = addArg(args, ArgDpiDesyncFakeUnknown, f.Unknown)
	args = addArg(args, ArgDpiDesyncFakeSynData, f.SynData)
	args = addArg(args, ArgDpiDesyncFakeTlsMod, f.TlsMod)
	args = addArg(args, ArgDpiDesyncFakeTcpMod, f.TcpMod)
	return args
}

func (s Strategy) argsSplit() []string {
	var args []string
	sp := s.Split
	args = addArg(args, ArgDpiDesyncSplitPos, sp.Pos)
	if sp.SeqOvl > 0 {
		args = addArgInt(args, ArgDpiDesyncSplitSeqOvl, sp.SeqOvl)
	}
	args = addArg(args, ArgDpiDesyncSplitPattern, sp.Pattern)

	if strings.Contains(s.Mode, "fakedsplit") || strings.Contains(s.Mode, "fakeddisorder") {
		args = addArg(args, ArgDpiDesyncFakedPattern, sp.FakedPattern)
		args = addArg(args, ArgDpiDesyncFakedMod, sp.FakedMod)
	}

	if strings.Contains(s.Mode, "hostfakesplit") {
		args = addArg(args, ArgDpiDesyncHostFakeMid, sp.HostMid)
		args = addArg(args, ArgDpiDesyncHostFakeMod, sp.HostMod)
	}

	if sp.IpFragPosTcp > 0 {
		args = addArgInt(args, ArgDpiDesyncIpFragPosTcp, sp.IpFragPosTcp)
	}
	if sp.IpFragPosUdp > 0 {
		args = addArgInt(args, ArgDpiDesyncIpFragPosUdp, sp.IpFragPosUdp)
	}
	return args
}

func (s Strategy) argsUdpLen() []string {
	var args []string
	args = addArgInt(args, ArgDpiDesyncUdpLenInc, s.UdpLen.Increment)
	args = addArg(args, ArgDpiDesyncUdpLenPattern, s.UdpLen.Pattern)
	return args
}

func (s Strategy) argsTTL() []string {
	var args []string
	t := s.TTL
	if t.Fixed > 0 {
		args = addArgInt(args, ArgDpiDesyncTTL, t.Fixed)
	}
	if t.Fixed6 > 0 {
		args = addArgInt(args, ArgDpiDesyncTTL6, t.Fixed6)
	}
	if t.AutoStr != "" {
		args = addArg(args, ArgDpiDesyncAutoTTL, t.AutoStr)
	} else if t.Auto > 0 {
		args = addArgInt(args, ArgDpiDesyncAutoTTL, t.Auto)
	}
	if t.Auto6 > 0 {
		args = addArgInt(args, ArgDpiDesyncAutoTTL6, t.Auto6)
	}
	return args
}

func (s Strategy) argsTcpFlags() []string {
	var args []string
	args = addArg(args, ArgDpiDesyncTcpFlagsSet, s.TcpFlags.Set)
	args = addArg(args, ArgDpiDesyncTcpFlagsUnset, s.TcpFlags.Unset)
	return args
}

func (s Strategy) argsWSS() []string {
	var args []string
	w := s.WSS
	if w.Enabled || w.Value != "" {
		val := w.Value
		if val == "" {
			val = "1:6"
		}
		args = append(args, fmt.Sprintf("%s=%s", ArgWSSize, val))
	}
	args = addArg(args, ArgWSSizeCutoff, w.Cutoff)
	if w.ForcedCutoff {
		args = append(args, ArgWSSizeForcedCutoff+"=1")
	}
	return args
}

func (s Strategy) argsTamper() []string {
	var args []string
	t := s.Tamper
	if t.HostCase {
		args = append(args, ArgHostCase)
	}
	if t.HostSpell != "" {
		args = append(args, ArgHostSpell+"="+t.HostSpell)
	}
	if t.HostNoSpace {
		args = append(args, ArgHostNoSpace)
	}
	if t.DomCase {
		args = append(args, ArgDomCase)
	}
	if t.MethodEol {
		args = append(args, ArgMethodEol)
	}
	if t.IpId != "" {
		args = append(args, ArgIpId+"="+t.IpId)
	}
	if t.SynAckSplit != "" {
		args = append(args, ArgSynAckSplit+"="+t.SynAckSplit)
	}
	return args
}

func (s Strategy) argsDup() []string {
	var args []string
	d := s.Dup
	if d.Count > 0 {
		args = addArgInt(args, ArgDup, d.Count)
	}
	if d.Replace {
		args = append(args, ArgDupReplace+"=1")
	}
	if d.TTL > 0 {
		args = addArgInt(args, ArgDupTTL, d.TTL)
	}
	if d.TTL6 > 0 {
		args = addArgInt(args, ArgDupTTL6, d.TTL6)
	}
	args = addArg(args, ArgDupAutoTTL, d.AutoTTL)
	args = addArg(args, ArgDupAutoTTL6, d.AutoTTL6)
	args = addArg(args, ArgDupFooling, d.Fooling)
	args = addArgInt(args, ArgDupTsInc, d.TsIncrement)
	args = addArgInt(args, ArgDupBadSeqInc, d.BadSeqIncrement)
	args = addArgInt(args, ArgDupBadAckInc, d.BadAckIncrement)
	args = addArg(args, ArgDupIpId, d.IpId)
	args = addArg(args, ArgDupStart, d.Start)
	args = addArg(args, ArgDupCutoff, d.Cutoff)
	args = addArg(args, ArgDupTcpFlagsSet, d.TcpFlagsSet)
	args = addArg(args, ArgDupTcpFlagsUnset, d.TcpFlagsUnset)
	return args
}

func (s Strategy) argsOrig() []string {
	var args []string
	o := s.Orig
	if o.TTL > 0 {
		args = addArgInt(args, ArgOrigTTL, o.TTL)
	}
	if o.TTL6 > 0 {
		args = addArgInt(args, ArgOrigTTL6, o.TTL6)
	}
	args = addArg(args, ArgOrigAutoTTL, o.AutoTTL)
	args = addArg(args, ArgOrigAutoTTL6, o.AutoTTL6)
	args = addArg(args, ArgOrigModStart, o.ModStart)
	args = addArg(args, ArgOrigModCutoff, o.ModCutoff)
	args = addArg(args, ArgOrigTcpFlagsSet, o.TcpFlagsSet)
	args = addArg(args, ArgOrigTcpFlagsUnset, o.TcpFlagsUnset)
	return args
}
