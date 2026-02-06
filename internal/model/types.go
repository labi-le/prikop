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
)

// StrategyConfig — это интерфейс, который должна реализовать стратегия NFQWS
type StrategyConfig interface {
	ToArgs() string
	String() string
}

// WorkerResult — результат работы контейнера (JSON output)
type WorkerResult struct {
	Success      bool     `json:"success"`
	Code         int      `json:"code"`
	Error        string   `json:"error,omitempty"`
	SuccessCount int      `json:"success_count"`
	TotalCount   int      `json:"total_count"`
	Passed       []string `json:"passed,omitempty"`
	Failed       []string `json:"failed,omitempty"`
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
