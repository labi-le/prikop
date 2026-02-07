package nfqws

import (
	"fmt"
	"strings"
)

// Strategy describes the nfqws arguments genome
type Strategy struct {
	Mode        string // --dpi-desync (comma separated list allowed)
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
	BadSeqIncrement int // --dpi-desync-badseq-increment
	BadAckIncrement int // --dpi-desync-badack-increment
	TsIncrement     int // --dpi-desync-ts-increment
}

type FakeOptions struct {
	TLS        string // --dpi-desync-fake-tls
	Quic       string // --dpi-desync-fake-quic
	Http       string // --dpi-desync-fake-http
	Wireguard  string // --dpi-desync-fake-wireguard
	Dht        string // --dpi-desync-fake-dht
	Discord    string // --dpi-desync-fake-discord
	Stun       string // --dpi-desync-fake-stun
	UnknownUdp string // --dpi-desync-fake-unknown-udp
	Unknown    string // --dpi-desync-fake-unknown
	SynData    string // --dpi-desync-fake-syndata
	TlsMod     string // --dpi-desync-fake-tls-mod
	TcpMod     string // --dpi-desync-fake-tcp-mod
}

type SplitOptions struct {
	Pos          string // --dpi-desync-split-pos
	SeqOvl       int    // --dpi-desync-split-seqovl
	Pattern      string // --dpi-desync-split-seqovl-pattern
	FakedPattern string // --dpi-desync-fakedsplit-pattern
	FakedMod     string // --dpi-desync-fakedsplit-mod
	HostMid      string // --dpi-desync-hostfakesplit-midhost
	HostMod      string // --dpi-desync-hostfakesplit-mod
	IpFragPosTcp int    // --dpi-desync-ipfrag-pos-tcp
	IpFragPosUdp int    // --dpi-desync-ipfrag-pos-udp
}

type UdpLenOptions struct {
	Increment int    // --dpi-desync-udplen-increment
	Pattern   string // --dpi-desync-udplen-pattern
}

type TTLOptions struct {
	Fixed   int    // --dpi-desync-ttl
	Fixed6  int    // --dpi-desync-ttl6
	Auto    int    // --dpi-desync-autottl
	Auto6   int    // --dpi-desync-autottl6
	AutoStr string // Raw string for autottl (e.g. "5:3-64") if complex format needed
}

type WSSOptions struct {
	Enabled      bool
	Value        string // --wssize
	Cutoff       string // --wssize-cutoff
	ForcedCutoff bool   // --wssize-forced-cutoff
}

type TamperOptions struct {
	HostCase    bool   // --hostcase
	HostSpell   string // --hostspell
	HostNoSpace bool   // --hostnospace
	DomCase     bool   // --domcase
	MethodEol   bool   // --methodeol
	IpId        string // --ip-id
	SynAckSplit string // --synack-split
}

type DupOptions struct {
	Count           int    // --dup
	Replace         bool   // --dup-replace
	TTL             int    // --dup-ttl
	TTL6            int    // --dup-ttl6
	AutoTTL         string // --dup-autottl
	AutoTTL6        string // --dup-autottl6
	Fooling         string // --dup-fooling
	TsIncrement     int    // --dup-ts-increment
	BadSeqIncrement int    // --dup-badseq-increment
	BadAckIncrement int    // --dup-badack-increment
	IpId            string // --dup-ip-id
	Start           string // --dup-start
	Cutoff          string // --dup-cutoff
	TcpFlagsSet     string // --dup-tcp-flags-set
	TcpFlagsUnset   string // --dup-tcp-flags-unset
}

type OrigOptions struct {
	TTL           int    // --orig-ttl
	TTL6          int    // --orig-ttl6
	AutoTTL       string // --orig-autottl
	AutoTTL6      string // --orig-autottl6
	TcpFlagsSet   string // --orig-tcp-flags-set
	TcpFlagsUnset string // --orig-tcp-flags-unset
	ModStart      string // --orig-mod-start
	ModCutoff     string // --orig-mod-cutoff
}

type TcpFlagsOptions struct {
	Set   string // --dpi-desync-tcp-flags-set
	Unset string // --dpi-desync-tcp-flags-unset
}

func (s Strategy) String() string {
	return s.ToArgs()
}

func (s Strategy) ToArgs() string {
	var args []string

	// --- DPI DESYNC MAIN ---
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

	// --- FOOLING ---
	var fooling []string
	if s.Fooling.Md5Sig {
		fooling = append(fooling, "md5sig")
	}
	if s.Fooling.BadSum {
		fooling = append(fooling, "badsum")
	}
	if s.Fooling.BadSeq {
		fooling = append(fooling, "badseq")
	}
	if s.Fooling.Ts {
		fooling = append(fooling, "ts")
	}
	if s.Fooling.Datanoack {
		fooling = append(fooling, "datanoack")
	}
	if s.Fooling.HopByHop {
		fooling = append(fooling, "hopbyhop")
	}
	if s.Fooling.HopByHop2 {
		fooling = append(fooling, "hopbyhop2")
	}
	if len(fooling) > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-fooling=%s", strings.Join(fooling, ",")))
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

	// --- FAKE ---
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

	// --- SPLIT ---
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

	// --- UDP LEN ---
	if s.UdpLen.Increment != 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-udplen-increment=%d", s.UdpLen.Increment))
	}
	if s.UdpLen.Pattern != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-udplen-pattern=%s", s.UdpLen.Pattern))
	}

	// --- TTL ---
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

	// --- TCP FLAGS ---
	if s.TcpFlags.Set != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-tcp-flags-set=%s", s.TcpFlags.Set))
	}
	if s.TcpFlags.Unset != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-tcp-flags-unset=%s", s.TcpFlags.Unset))
	}

	// --- WSS ---
	if s.WSS.Enabled || s.WSS.Value != "" {
		val := s.WSS.Value
		if val == "" {
			val = "1:6" // Default if enabled but empty
		}
		args = append(args, fmt.Sprintf("--wssize=%s", val))
	}
	if s.WSS.Cutoff != "" {
		args = append(args, fmt.Sprintf("--wssize-cutoff=%s", s.WSS.Cutoff))
	}
	if s.WSS.ForcedCutoff {
		args = append(args, "--wssize-forced-cutoff=1")
	}

	// --- TAMPER ---
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

	// --- DUP ---
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

	// --- ORIG ---
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

	return strings.Join(args, " ")
}
