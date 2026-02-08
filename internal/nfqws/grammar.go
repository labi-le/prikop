package nfqws

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
	ArgDpiDesync               = "--dpi-desync"
	ArgDpiDesyncRepeats        = "--dpi-desync-repeats"
	ArgDpiDesyncAnyProtocol    = "--dpi-desync-any-protocol"
	ArgDpiDesyncSkipNoSNI      = "--dpi-desync-skip-nosni"
	ArgDpiDesyncCutoff         = "--dpi-desync-cutoff"
	ArgDpiDesyncStart          = "--dpi-desync-start"
	ArgDpiDesyncFwmark         = "--dpi-desync-fwmark"
	ArgDpiDesyncFooling        = "--dpi-desync-fooling"
	ArgDpiDesyncBadSeqInc      = "--dpi-desync-badseq-increment"
	ArgDpiDesyncBadAckInc      = "--dpi-desync-badack-increment"
	ArgDpiDesyncTsInc          = "--dpi-desync-ts-increment"
	ArgDpiDesyncFakeTls        = "--dpi-desync-fake-tls"
	ArgDpiDesyncFakeQuic       = "--dpi-desync-fake-quic"
	ArgDpiDesyncFakeHttp       = "--dpi-desync-fake-http"
	ArgDpiDesyncFakeWireguard  = "--dpi-desync-fake-wireguard"
	ArgDpiDesyncFakeDht        = "--dpi-desync-fake-dht"
	ArgDpiDesyncFakeDiscord    = "--dpi-desync-fake-discord"
	ArgDpiDesyncFakeStun       = "--dpi-desync-fake-stun"
	ArgDpiDesyncFakeUnknownUdp = "--dpi-desync-fake-unknown-udp"
	ArgDpiDesyncFakeUnknown    = "--dpi-desync-fake-unknown"
	ArgDpiDesyncFakeSynData    = "--dpi-desync-fake-syndata"
	ArgDpiDesyncFakeTlsMod     = "--dpi-desync-fake-tls-mod"
	ArgDpiDesyncFakeTcpMod     = "--dpi-desync-fake-tcp-mod"
	ArgDpiDesyncSplitPos       = "--dpi-desync-split-pos"
	ArgDpiDesyncSplitSeqOvl    = "--dpi-desync-split-seqovl"
	ArgDpiDesyncSplitPattern   = "--dpi-desync-split-seqovl-pattern"
	ArgDpiDesyncFakedPattern   = "--dpi-desync-fakedsplit-pattern"
	ArgDpiDesyncFakedMod       = "--dpi-desync-fakedsplit-mod"
	ArgDpiDesyncHostFakeMid    = "--dpi-desync-hostfakesplit-midhost"
	ArgDpiDesyncHostFakeMod    = "--dpi-desync-hostfakesplit-mod"
	ArgDpiDesyncIpFragPosTcp   = "--dpi-desync-ipfrag-pos-tcp"
	ArgDpiDesyncIpFragPosUdp   = "--dpi-desync-ipfrag-pos-udp"
	ArgDpiDesyncUdpLenInc      = "--dpi-desync-udplen-increment"
	ArgDpiDesyncUdpLenPattern  = "--dpi-desync-udplen-pattern"
	ArgDpiDesyncTTL            = "--dpi-desync-ttl"
	ArgDpiDesyncTTL6           = "--dpi-desync-ttl6"
	ArgDpiDesyncAutoTTL        = "--dpi-desync-autottl"
	ArgDpiDesyncAutoTTL6       = "--dpi-desync-autottl6"
	ArgDpiDesyncTcpFlagsSet    = "--dpi-desync-tcp-flags-set"
	ArgDpiDesyncTcpFlagsUnset  = "--dpi-desync-tcp-flags-unset"
	ArgWSSize                  = "--wssize"
	ArgWSSizeCutoff            = "--wssize-cutoff"
	ArgWSSizeForcedCutoff      = "--wssize-forced-cutoff"
	ArgHostCase                = "--hostcase"
	ArgHostSpell               = "--hostspell"
	ArgHostNoSpace             = "--hostnospace"
	ArgDomCase                 = "--domcase"
	ArgMethodEol               = "--methodeol"
	ArgIpId                    = "--ip-id"
	ArgSynAckSplit             = "--synack-split"
	ArgDup                     = "--dup"
	ArgDupReplace              = "--dup-replace"
	ArgDupTTL                  = "--dup-ttl"
	ArgDupTTL6                 = "--dup-ttl6"
	ArgDupAutoTTL              = "--dup-autottl"
	ArgDupAutoTTL6             = "--dup-autottl6"
	ArgDupFooling              = "--dup-fooling"
	ArgDupTsInc                = "--dup-ts-increment"
	ArgDupBadSeqInc            = "--dup-badseq-increment"
	ArgDupBadAckInc            = "--dup-badack-increment"
	ArgDupIpId                 = "--dup-ip-id"
	ArgDupStart                = "--dup-start"
	ArgDupCutoff               = "--dup-cutoff"
	ArgDupTcpFlagsSet          = "--dup-tcp-flags-set"
	ArgDupTcpFlagsUnset        = "--dup-tcp-flags-unset"
	ArgOrigTTL                 = "--orig-ttl"
	ArgOrigTTL6                = "--orig-ttl6"
	ArgOrigAutoTTL             = "--orig-autottl"
	ArgOrigAutoTTL6            = "--orig-autottl6"
	ArgOrigModStart            = "--orig-mod-start"
	ArgOrigModCutoff           = "--orig-mod-cutoff"
	ArgOrigTcpFlagsSet         = "--orig-tcp-flags-set"
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
