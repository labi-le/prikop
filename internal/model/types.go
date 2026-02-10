package model

import (
	"time"
)

const (
	QueueNum          = "200"
	ImageName         = "prikop:latest"
	ContainerTimeout  = 15 * time.Second
	MaxWorkers        = 50
	CheckTimeout      = 4000 * time.Millisecond
	TargetSuccessRate = 80
	WorkerMemoryLimit = 60 * 1024 * 1024 // 60 MB
	SocketDir         = "/var/run/prikop"
)

// WorkerRequest отправляется оркестратором воркеру
type WorkerRequest struct {
	StrategyArgs []string `json:"strategy_args"`
	Filters      []string `json:"filters"` // NEW FIELD
	TargetGroup  string   `json:"target_group"`
}

// StrategyConfig — это интерфейс, который должна реализовать стратегия NFQWS
type StrategyConfig interface {
	ToArgs() []string
	String() string
}

// WorkerResult — результат работы контейнера (JSON output)
type WorkerResult struct {
	Success      bool          `json:"success"`
	FailureType  FailureReason `json:"failure_type"` // NEW field
	Error        string        `json:"error,omitempty"`
	SuccessCount int           `json:"success_count"`
	TotalCount   int           `json:"total_count"`
	Passed       []string      `json:"passed,omitempty"`
	Failed       []string      `json:"failed,omitempty"`
}

// ScoredStrategy — стратегия с метриками для эволюции
type ScoredStrategy struct {
	Config     StrategyConfig
	RawArgs    string
	Duration   time.Duration
	Result     WorkerResult
	SystemLogs string
	Complexity int
}

// ReconReport holds the results of the active reconnaissance phase
type ReconReport struct {
	IPFragWorks bool
	BadSumWorks bool
}

type FailureReason string

const (
	ReasonNone     FailureReason = ""
	ReasonTimeout  FailureReason = "timeout"  // DPI Drop or Blackhole
	ReasonReset    FailureReason = "reset"    // DPI Active Reject
	ReasonThrottle FailureReason = "throttle" // DPI Shaping/Slowdown
	ReasonTLS      FailureReason = "tls"      // DPI TLS Corruption (bad MAC, decrypt error, handshake failure)
	ReasonUnknown  FailureReason = "unknown"
)
