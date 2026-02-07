package verifier

import (
	"context"
	"prikop/internal/model"
)

// CheckResult результат проверки одной группы целей
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
	Threshold    int    // байт для успеха
	Proto        string // tcp, udp, quic
	IgnoreStatus bool
}
