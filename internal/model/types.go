package model

import (
	"fmt"
	"strings"
	"time"
)

const (
	QueueNum  = "200"
	ImageName = "prikop:latest"

	ContainerTimeout       = 10 * time.Second
	MaxWorkers             = 50
	MaxTotalAttempts       = 8000
	DefaultBinaryThreshold = 64 * 1024
	DefaultWebThreshold    = 1
	CheckTimeout           = 4000 * time.Millisecond

	// Evolution Constants
	MaxGenerations    = 5  // Общий лимит, если не переопределен фазой
	TargetSuccessRate = 95 // Целевой % успеха, чтобы считать стратегию "идеальной"
	PopulationSize    = 100
	ElitesCount       = 8
)

type Target struct {
	ID           string
	Provider     string
	URL          string
	Times        int
	Threshold    int
	Proto        string
	IgnoreStatus bool
}

type WorkerResult struct {
	Success      bool   `json:"success"`
	Code         int    `json:"code"`
	Error        string `json:"error,omitempty"`
	SuccessCount int    `json:"success_count"`
	TotalCount   int    `json:"total_count"`
}

type StrategyResult struct {
	Strategy string
	Duration time.Duration
	WorkerResult
	SystemLogs string
}

type DPIConfig struct {
	Mode        string
	Repeats     int
	Fooling     string
	FakeTLS     string
	FakeTLSMod  string
	TTL         int
	AutoTTL     int
	SplitPos    string
	SplitSeqOvl int
	Wssize      string
	AnyProtocol bool
	Cutoff      string
}

func (c DPIConfig) String() string {
	parts := []string{fmt.Sprintf("--dpi-desync=%s", c.Mode)}

	if c.Repeats > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-repeats=%d", c.Repeats))
	}

	if c.Mode == "ipfrag2" && c.SplitPos != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-ipfrag-pos-udp=%s", c.SplitPos))
	} else if c.SplitPos != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-split-pos=%s", c.SplitPos))
	}

	if c.SplitSeqOvl > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-split-seqovl=%d", c.SplitSeqOvl))
	}
	if c.Wssize != "" {
		parts = append(parts, fmt.Sprintf("--wssize=%s", c.Wssize))
	}
	if c.Fooling != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-fooling=%s", c.Fooling))
	}

	if c.FakeTLS != "" {
		if strings.Contains(c.FakeTLS, "quic") {
			parts = append(parts, fmt.Sprintf("--dpi-desync-fake-quic=%s", c.FakeTLS))
		} else {
			parts = append(parts, fmt.Sprintf("--dpi-desync-fake-tls=%s", c.FakeTLS))
		}

		if c.FakeTLSMod != "" {
			parts = append(parts, fmt.Sprintf("--dpi-desync-fake-tls-mod=%s", c.FakeTLSMod))
		}
	}

	if c.TTL > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-ttl=%d", c.TTL))
	} else if c.AutoTTL > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-autottl=%d", c.AutoTTL))
	}
	if c.Cutoff != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-cutoff=%s", c.Cutoff))
	}
	if c.AnyProtocol {
		parts = append(parts, "--dpi-desync-any-protocol")
	}
	return strings.Join(parts, " ")
}
