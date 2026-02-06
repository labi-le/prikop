package verifier

import (
	"context"
)

// CheckResult результат проверки одной группы целей
type CheckResult struct {
	Success      bool
	SuccessCount int
	TotalCount   int
	Details      string
	PassedUrls   []string
	FailedUrls   []string
}

// Verifier интерфейс для всех тест-кейсов
type Verifier interface {
	Name() string
	// Run запускает проверку. Должен вызываться ВНУТРИ контейнера.
	Run(ctx context.Context) CheckResult
}

// Target структура цели для проверки
type Target struct {
	URL          string
	Threshold    int    // байт для успеха
	Proto        string // tcp, udp, quic
	IgnoreStatus bool
}
