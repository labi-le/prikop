package nfqws

import (
	"fmt"
	"strings"
)

// Strategy describes the nfqws arguments genome
type Strategy struct {
	Mode        string // --dpi-desync
	Repeats     int    // --dpi-desync-repeats
	AnyProtocol bool   // --dpi-desync-any-protocol
	SkipNoSNI   bool   // --dpi-desync-skip-nosni
	Cutoff      string // --dpi-desync-cutoff
	Start       string // --dpi-desync-start
	FwMark      string // --dpi-desync-fwmark

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
	Pos          string
	SeqOvl       int
	Pattern      string
	FakedPattern string
	FakedMod     string
	HostMid      string
	HostMod      string
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

func (s Strategy) String() string {
	return s.ToArgs()
}

func (s Strategy) ToArgs() string {
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

	return strings.Join(args, " ")
}

func (s Strategy) argsMain() []string {
	var args []string
	if s.Mode != "" {
		args = append(args, fmt.Sprintf("--dpi-desync=%s", s.Mode))
	}
	if s.Repeats > 1 {
		args = append(args, fmt.Sprintf("--dpi-desync-repeats=%d", s.Repeats))
	}
	if s.AnyProtocol {
		args = append(args, "--dpi-desync-any-protocol")
	}
	if s.SkipNoSNI {
		args = append(args, "--dpi-desync-skip-nosni=1")
	}
	if s.Cutoff != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-cutoff=%s", s.Cutoff))
	}
	if s.Start != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-start=%s", s.Start))
	}
	if s.FwMark != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fwmark=%s", s.FwMark))
	}
	return args
}

func (s Strategy) argsFooling() []string {
	var args []string
	var flags []string
	if s.Fooling.Md5Sig {
		flags = append(flags, "md5sig")
	}
	if s.Fooling.BadSum {
		flags = append(flags, "badsum")
	}
	if s.Fooling.BadSeq {
		flags = append(flags, "badseq")
	}
	if s.Fooling.Ts {
		flags = append(flags, "ts")
	}
	if s.Fooling.Datanoack {
		flags = append(flags, "datanoack")
	}
	if s.Fooling.HopByHop {
		flags = append(flags, "hopbyhop")
	}
	if s.Fooling.HopByHop2 {
		flags = append(flags, "hopbyhop2")
	}
	if len(flags) > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-fooling=%s", strings.Join(flags, ",")))
	}
	if s.Fooling.BadSeqIncrement != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-badseq-increment=%d", s.Fooling.BadSeqIncrement))
	}
	if s.Fooling.BadAckIncrement != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-badack-increment=%d", s.Fooling.BadAckIncrement))
	}
	if s.Fooling.TsIncrement != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ts-increment=%d", s.Fooling.TsIncrement))
	}
	return args
}

func (s Strategy) argsFake() []string {
	var args []string
	if s.Fake.TLS != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tls=%s", s.Fake.TLS))
	}
	if s.Fake.Quic != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-quic=%s", s.Fake.Quic))
	}
	if s.Fake.Http != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-http=%s", s.Fake.Http))
	}
	if s.Fake.Wireguard != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-wireguard=%s", s.Fake.Wireguard))
	}
	if s.Fake.Dht != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-dht=%s", s.Fake.Dht))
	}
	if s.Fake.Discord != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-discord=%s", s.Fake.Discord))
	}
	if s.Fake.Stun != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-stun=%s", s.Fake.Stun))
	}
	if s.Fake.UnknownUdp != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-unknown-udp=%s", s.Fake.UnknownUdp))
	}
	if s.Fake.Unknown != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-unknown=%s", s.Fake.Unknown))
	}
	if s.Fake.SynData != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-syndata=%s", s.Fake.SynData))
	}
	if s.Fake.TlsMod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tls-mod=%s", s.Fake.TlsMod))
	}
	if s.Fake.TcpMod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tcp-mod=%s", s.Fake.TcpMod))
	}
	return args
}

func (s Strategy) argsSplit() []string {
	var args []string
	if s.Split.Pos != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-split-pos=%s", s.Split.Pos))
	}
	if s.Split.SeqOvl > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl=%d", s.Split.SeqOvl))
	}
	if s.Split.Pattern != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl-pattern=%s", s.Split.Pattern))
	}
	if s.Split.FakedPattern != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fakedsplit-pattern=%s", s.Split.FakedPattern))
	}
	if s.Split.FakedMod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fakedsplit-mod=%s", s.Split.FakedMod))
	}
	if s.Split.HostMid != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-hostfakesplit-midhost=%s", s.Split.HostMid))
	}
	if s.Split.HostMod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-hostfakesplit-mod=%s", s.Split.HostMod))
	}
	if s.Split.IpFragPosTcp > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ipfrag-pos-tcp=%d", s.Split.IpFragPosTcp))
	}
	if s.Split.IpFragPosUdp > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ipfrag-pos-udp=%d", s.Split.IpFragPosUdp))
	}
	return args
}

func (s Strategy) argsUdpLen() []string {
	var args []string
	if s.UdpLen.Increment != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-udplen-increment=%d", s.UdpLen.Increment))
	}
	if s.UdpLen.Pattern != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-udplen-pattern=%s", s.UdpLen.Pattern))
	}
	return args
}

func (s Strategy) argsTTL() []string {
	var args []string
	if s.TTL.Fixed > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ttl=%d", s.TTL.Fixed))
	}
	if s.TTL.Fixed6 > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ttl6=%d", s.TTL.Fixed6))
	}
	if s.TTL.AutoStr != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-autottl=%s", s.TTL.AutoStr))
	} else if s.TTL.Auto > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-autottl=%d", s.TTL.Auto))
	}
	if s.TTL.Auto6 > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-autottl6=%d", s.TTL.Auto6))
	}
	return args
}

func (s Strategy) argsTcpFlags() []string {
	var args []string
	if s.TcpFlags.Set != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-tcp-flags-set=%s", s.TcpFlags.Set))
	}
	if s.TcpFlags.Unset != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-tcp-flags-unset=%s", s.TcpFlags.Unset))
	}
	return args
}

func (s Strategy) argsWSS() []string {
	var args []string
	if s.WSS.Enabled || s.WSS.Value != "" {
		val := s.WSS.Value
		if val == "" {
			val = "1:6"
		}
		args = append(args, fmt.Sprintf("--wssize=%s", val))
	}
	if s.WSS.Cutoff != "" {
		args = append(args, fmt.Sprintf("--wssize-cutoff=%s", s.WSS.Cutoff))
	}
	if s.WSS.ForcedCutoff {
		args = append(args, "--wssize-forced-cutoff=1")
	}
	return args
}

func (s Strategy) argsTamper() []string {
	var args []string
	if s.Tamper.HostCase {
		args = append(args, "--hostcase")
	}
	if s.Tamper.HostSpell != "" {
		args = append(args, "--hostspell="+s.Tamper.HostSpell)
	}
	if s.Tamper.HostNoSpace {
		args = append(args, "--hostnospace")
	}
	if s.Tamper.DomCase {
		args = append(args, "--domcase")
	}
	if s.Tamper.MethodEol {
		args = append(args, "--methodeol")
	}
	if s.Tamper.IpId != "" {
		args = append(args, "--ip-id="+s.Tamper.IpId)
	}
	if s.Tamper.SynAckSplit != "" {
		args = append(args, "--synack-split="+s.Tamper.SynAckSplit)
	}
	return args
}

func (s Strategy) argsDup() []string {
	var args []string
	if s.Dup.Count > 0 {
		args = append(args, fmt.Sprintf("--dup=%d", s.Dup.Count))
	}
	if s.Dup.Replace {
		args = append(args, "--dup-replace=1")
	}
	if s.Dup.TTL > 0 {
		args = append(args, fmt.Sprintf("--dup-ttl=%d", s.Dup.TTL))
	}
	if s.Dup.TTL6 > 0 {
		args = append(args, fmt.Sprintf("--dup-ttl6=%d", s.Dup.TTL6))
	}
	if s.Dup.AutoTTL != "" {
		args = append(args, fmt.Sprintf("--dup-autottl=%s", s.Dup.AutoTTL))
	}
	if s.Dup.AutoTTL6 != "" {
		args = append(args, fmt.Sprintf("--dup-autottl6=%s", s.Dup.AutoTTL6))
	}
	if s.Dup.Fooling != "" {
		args = append(args, fmt.Sprintf("--dup-fooling=%s", s.Dup.Fooling))
	}
	if s.Dup.TsIncrement != 0 {
		args = append(args, fmt.Sprintf("--dup-ts-increment=%d", s.Dup.TsIncrement))
	}
	if s.Dup.BadSeqIncrement != 0 {
		args = append(args, fmt.Sprintf("--dup-badseq-increment=%d", s.Dup.BadSeqIncrement))
	}
	if s.Dup.BadAckIncrement != 0 {
		args = append(args, fmt.Sprintf("--dup-badack-increment=%d", s.Dup.BadAckIncrement))
	}
	if s.Dup.IpId != "" {
		args = append(args, fmt.Sprintf("--dup-ip-id=%s", s.Dup.IpId))
	}
	if s.Dup.Start != "" {
		args = append(args, fmt.Sprintf("--dup-start=%s", s.Dup.Start))
	}
	if s.Dup.Cutoff != "" {
		args = append(args, fmt.Sprintf("--dup-cutoff=%s", s.Dup.Cutoff))
	}
	if s.Dup.TcpFlagsSet != "" {
		args = append(args, fmt.Sprintf("--dup-tcp-flags-set=%s", s.Dup.TcpFlagsSet))
	}
	if s.Dup.TcpFlagsUnset != "" {
		args = append(args, fmt.Sprintf("--dup-tcp-flags-unset=%s", s.Dup.TcpFlagsUnset))
	}
	return args
}

func (s Strategy) argsOrig() []string {
	var args []string
	if s.Orig.TTL > 0 {
		args = append(args, fmt.Sprintf("--orig-ttl=%d", s.Orig.TTL))
	}
	if s.Orig.TTL6 > 0 {
		args = append(args, fmt.Sprintf("--orig-ttl6=%d", s.Orig.TTL6))
	}
	if s.Orig.AutoTTL != "" {
		args = append(args, fmt.Sprintf("--orig-autottl=%s", s.Orig.AutoTTL))
	}
	if s.Orig.AutoTTL6 != "" {
		args = append(args, fmt.Sprintf("--orig-autottl6=%s", s.Orig.AutoTTL6))
	}
	if s.Orig.ModStart != "" {
		args = append(args, fmt.Sprintf("--orig-mod-start=%s", s.Orig.ModStart))
	}
	if s.Orig.ModCutoff != "" {
		args = append(args, fmt.Sprintf("--orig-mod-cutoff=%s", s.Orig.ModCutoff))
	}
	if s.Orig.TcpFlagsSet != "" {
		args = append(args, fmt.Sprintf("--orig-tcp-flags-set=%s", s.Orig.TcpFlagsSet))
	}
	if s.Orig.TcpFlagsUnset != "" {
		args = append(args, fmt.Sprintf("--orig-tcp-flags-unset=%s", s.Orig.TcpFlagsUnset))
	}
	return args
}
