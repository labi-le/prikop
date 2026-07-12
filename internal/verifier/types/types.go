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
	// DownloadCheck makes the DPI step a real GET that must stream the full
	// response body to EOF within Timeout (and, if set, at >= MinSpeed). It
	// catches response-side download-throttling — a body that starts then
	// stalls — which the HEAD/handshake and the 64 KiB POST (an upload) cannot
	// see. Use it for package caches where completing a large download IS the goal.
	DownloadCheck bool
	// NoRedirect stops the checker following HTTP redirects, so the test stays on
	// the target's own SNI instead of silently measuring a redirect destination
	// (e.g. a mirror 30x-ing to a different origin). Default follows redirects.
	NoRedirect bool
	MinSpeed   float64
	Timeout    time.Duration
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
