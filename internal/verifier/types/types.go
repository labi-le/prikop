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
	// HandshakeOnly makes the checker PASS on a completed TLS handshake + HEAD
	// (the site opens) and skip the 64 KiB POST. For targets the app only needs
	// to reach, where the POST models an upload the DPI throttles independently.
	HandshakeOnly bool
	MinSpeed      float64
	Timeout       time.Duration
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
