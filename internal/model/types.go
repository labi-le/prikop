package model

import (
	"time"
)

const (
	QueueNum               = "200"
	ImageName              = "prikop:latest"
	ContainerTimeout       = 40 * time.Second
	MaxWorkers             = 50
	MaxConcurrentProviders = 1
	CheckTimeout           = 30 * time.Second
	TargetSuccessRate      = 80
	WorkerMemoryLimit      = 60 * 1024 * 1024 // 60 MB
	SocketDir              = "/var/run/prikop"
	TargetsDir             = "/app/targets"
)

// WorkerRequest отправляется оркестратором воркеру
type WorkerRequest struct {
	StrategyArgs []string `json:"strategy_args"`
	Filters      []string `json:"filters"`
	TargetGroup  string   `json:"target_group"`
	MaxTargets   int      `json:"max_targets"` // 0 means all
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
	ReasonDNS      FailureReason = "dns"      // DNS resolution failure
	ReasonCIDR     FailureReason = "cidr"     // Target IP not in CIDR range
	ReasonSkip     FailureReason = "skip"     // Inconclusive result (probably unreachable)
	ReasonUnknown  FailureReason = "unknown"

	ReasonTLSALPN             FailureReason = "tls_alpn"              // DPI навязал ALPN (h2/http1.1) без запроса
	ReasonTLSVersion          FailureReason = "tls_version"           // Блокировка TLS 1.3 / downgrade attack
	ReasonTLSNotTLS           FailureReason = "tls_not_tls"           // DPI вернул HTML-заглушку или мусор вместо ServerHello
	ReasonTLSOversized        FailureReason = "tls_oversized"         // Oversized record — DPI склеил пакеты или plain-text ответ
	ReasonTLSBadMAC           FailureReason = "tls_bad_mac"           // DPI повредил MAC записи
	ReasonTLSDecrypt          FailureReason = "tls_decrypt"           // Ошибка расшифровки сообщения
	ReasonTLSDecode           FailureReason = "tls_decode"            // Ошибка декодирования TLS-сообщения (remote error: error decoding message)
	ReasonTLSAlertUnexpected  FailureReason = "tls_alert_unexpected"  // Нарушение порядка сообщений (state machine error)
	ReasonTLSHandshake        FailureReason = "tls_handshake"         // Общий сбой handshake
	ReasonTLSInternal         FailureReason = "tls_internal"          // Remote TLS internal error
	ReasonTLSSessionID        FailureReason = "tls_session_id"        // Сервер не вернул legacy session ID
	ReasonTLSUnrecognizedName FailureReason = "tls_unrecognized_name" // SNI mismatch / DPI spoofed alert
	ReasonTLSDowngrade        FailureReason = "tls_downgrade"         // Downgrade attempt detected — MitM или broken middlebox
	ReasonTLSBadSignature     FailureReason = "tls_bad_signature"     // Невалидная подпись сертификата — MitM подмена
	ReasonTLSCipherSuite      FailureReason = "tls_cipher_suite"      // Сервер выбрал cipher suite, который клиент не предлагал — MitM / broken middlebox
	ReasonTLSRecordOverflow   FailureReason = "tls_record_overflow"   // TLS record overflow — DPI инжектировал данные или повредил запись
	ReasonTLSIllegalParam     FailureReason = "tls_illegal_param"     // Illegal parameter в handshake — DPI подменил/повредил поле
)

func (r FailureReason) IsTLS() bool {
	return len(r) > 4 && r[:4] == "tls_"
}
