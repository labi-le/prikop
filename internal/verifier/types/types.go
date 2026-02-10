package types

import (
	"context"
	"prikop/internal/model"
	"time"
)

type Protocol int

const (
	ProtoTCP Protocol = iota
	ProtoQUIC
	ProtoSTUN
)

func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoQUIC:
		return "quic"
	case ProtoSTUN:
		return "stun"
	default:
		return "unknown"
	}
}

type CheckResult struct {
	Success       bool
	SuccessCount  int
	TotalCount    int
	Details       string
	PassedUrls    []string
	FailedUrls    []string
	FailureReason model.FailureReason
}

type Verifier interface {
	Name() string
	Run(ctx context.Context) CheckResult
}

type Target struct {
	URL          string
	Threshold    int
	Proto        Protocol
	IgnoreStatus bool
	MinSpeed     float64
	Timeout      time.Duration
}

type ProviderDefinition struct {
	Name       string
	CIDRSource string
	CIDRFile   string
	Targets    []Target
	Gens       int
}
