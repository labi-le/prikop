package nfqws

import (
	"fmt"
	"strings"
)

// Strategy описывает геном настройки nfqws
type Strategy struct {
	Mode        string // fake, multisplit, multidisorder, fakedsplit, ipfrag1
	Repeats     int
	Fooling     FoolingSet
	Fake        FakeOptions
	Split       SplitOptions
	TTL         TTLOptions
	WSS         WSSOptions
	AnyProtocol bool
	Cutoff      string // "", "d2", "n2"
}

type FoolingSet struct {
	Md5Sig    bool
	BadSum    bool
	BadSeq    bool
	Ts        bool
	Datanoack bool
}

type FakeOptions struct {
	TLS  string // path to bin
	Quic string // path to bin
	Mod  string // none, rnd, rndsni
}

type SplitOptions struct {
	Pos     string // 1, 2, 1+sniext...
	SeqOvl  int
	Pattern string // path to bin (fake) used as pattern
}

type TTLOptions struct {
	Fixed int
	Auto  int
}

type WSSOptions struct {
	Enabled bool
	Value   string
}

func (s Strategy) String() string {
	return s.ToArgs()
}

func (s Strategy) ToArgs() string {
	var args []string

	if s.Mode == "" {
		return ""
	}
	args = append(args, fmt.Sprintf("--dpi-desync=%s", s.Mode))

	if s.Repeats > 1 {
		args = append(args, fmt.Sprintf("--dpi-desync-repeats=%d", s.Repeats))
	}

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
	if len(fooling) > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-fooling=%s", strings.Join(fooling, ",")))
	}

	if s.Fake.TLS != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tls=%s", s.Fake.TLS))
	}
	if s.Fake.Quic != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-quic=%s", s.Fake.Quic))
	}
	if (s.Fake.TLS != "" || s.Fake.Quic != "") && s.Fake.Mod != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-fake-tls-mod=%s", s.Fake.Mod))
	}

	if s.Split.Pos != "" {
		if s.Mode == "ipfrag2" {
			args = append(args, fmt.Sprintf("--dpi-desync-ipfrag-pos-udp=%s", s.Split.Pos))
		} else {
			args = append(args, fmt.Sprintf("--dpi-desync-split-pos=%s", s.Split.Pos))
		}
	}
	if s.Split.SeqOvl > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl=%d", s.Split.SeqOvl))
		if s.Split.Pattern != "" {
			args = append(args, fmt.Sprintf("--dpi-desync-split-seqovl-pattern=%s", s.Split.Pattern))
		}
	}

	if s.TTL.Fixed > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-ttl=%d", s.TTL.Fixed))
	} else if s.TTL.Auto > 0 {
		args = append(args, fmt.Sprintf("--dpi-desync-autottl=%d", s.TTL.Auto))
	}

	if s.WSS.Enabled {
		val := s.WSS.Value
		if val == "" {
			val = "1:6"
		}
		args = append(args, fmt.Sprintf("--wssize=%s", val))
	}

	if s.AnyProtocol {
		args = append(args, "--dpi-desync-any-protocol")
	}
	if s.Cutoff != "" {
		args = append(args, fmt.Sprintf("--dpi-desync-cutoff=%s", s.Cutoff))
	}

	return strings.Join(args, " ")
}
