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
)

func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoQUIC:
		return "quic"
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
	Run(ctx context.Context, maxTargets int) CheckResult
}

type Target struct {
	ID           string
	URL          string
	SNI          string
	Threshold    int
	Proto        Protocol
	IgnoreStatus bool
	MinSpeed     float64
	Timeout      time.Duration
}

type ProviderDefinition struct {
	Name             string
	CIDRSource       string
	CIDRFile         string
	Targets          []Target
	Gens             int
	Filters          string
	Proto            string  // "tcp" or "udp"
	SuccessThreshold float64 // 0.0 to 1.0, defaults to 1.0 if 0
}
