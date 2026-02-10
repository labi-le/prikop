package checker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"prikop/internal/model"
	"strings"
	"syscall"
)

// AnalyzeError классифицирует ошибку сетевого запроса в FailureReason.
// Не зависит от конкретной HTTP-библиотеки.
func AnalyzeError(err error) model.FailureReason {
	if err == nil {
		return model.ReasonNone
	}

	// Unwrap url.Error (net/http оборачивает ошибки)
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}

	// --- Type-based checks ---

	if errors.Is(err, context.DeadlineExceeded) {
		return model.ReasonTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.ReasonTimeout
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return model.ReasonReset
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.ECONNRESET) ||
				errors.Is(sysErr.Err, syscall.ECONNABORTED) ||
				errors.Is(sysErr.Err, syscall.EPIPE) {
				return model.ReasonReset
			}
		}
	}

	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		if errors.Is(syscallErr.Err, syscall.ECONNRESET) ||
			errors.Is(syscallErr.Err, syscall.ECONNABORTED) ||
			errors.Is(syscallErr.Err, syscall.EPIPE) {
			return model.ReasonReset
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return model.ReasonDNS
	}

	// --- String matching ---
	// Необходимо, так как crypto/tls возвращает простые errors.New()
	msg := err.Error()

	// TLS: Вмешательство DPI (Specific Interventions)

	// Самая частая ошибка РКН/ТСПУ: навязывание ALPN (h2/http1.1) без запроса
	if strings.Contains(msg, "server advertised unrequested ALPN extension") {
		return model.ReasonTLSALPN
	}

	// Блокировка TLS 1.3 или попытка понизить версию (Downgrade Attack)
	if strings.Contains(msg, "protocol version not supported") ||
		strings.Contains(msg, "remote error: protocol version") {
		return model.ReasonTLSVersion
	}

	// Ответ не похож на TLS (DPI вернул HTML-заглушку или мусор вместо ServerHello)
	if strings.Contains(msg, "first record does not look like a TLS handshake") ||
		strings.Contains(msg, "server gave HTTP response to HTTPS client") {
		return model.ReasonTLSNotTLS
	}

	// Слишком длинная запись (DPI склеил пакеты или сервер ответил plain-text'ом на TLS запрос)
	// Часто бывает, если ttl фейка слишком большой и он дошел до сервера
	if strings.Contains(msg, "oversized record received") {
		return model.ReasonTLSOversized
	}

	// MITM
	if strings.Contains(msg, "certificate signed by unknown authority") {
		return model.ReasonTLSCertUnknown
	}

	// MITM: expired cert
	if strings.Contains(msg, "certificate has expired or is not yet valid") {
		return model.ReasonTLSCertExpired
	}

	// MITM: name mismatch
	if strings.Contains(msg, "certificate is valid for") ||
		strings.Contains(msg, "x509: certificate is not valid for any names") {
		return model.ReasonTLSCertMismatch
	}

	// MITM: invalid signature
	if strings.Contains(msg, "invalid signature") {
		return model.ReasonTLSBadSignature
	}

	// Downgrade attack detected by crypto/tls
	if strings.Contains(msg, "downgrade attempt detected") {
		return model.ReasonTLSDowngrade
	}

	if strings.Contains(msg, "bad record MAC") || strings.Contains(msg, "tls: bad record MAC") {
		return model.ReasonTLSBadMAC
	}

	if strings.Contains(msg, "error decrypting message") {
		return model.ReasonTLSDecrypt
	}

	if strings.Contains(msg, "error decoding message") {
		return model.ReasonTLSDecode
	}

	if strings.Contains(msg, "unconfigured cipher suite") {
		return model.ReasonTLSCipherSuite
	}

	if strings.Contains(msg, "record overflow") {
		return model.ReasonTLSRecordOverflow
	}

	if strings.Contains(msg, "illegal parameter") {
		return model.ReasonTLSIllegalParam
	}

	// Нарушение порядка сообщений (State Machine Error) - бывает из-за --dpi-desync=disorder
	if strings.Contains(msg, "unexpected message") {
		return model.ReasonTLSAlertUnexpected
	}

	if strings.Contains(msg, "tls: handshake failure") {
		return model.ReasonTLSHandshake
	}
	if strings.Contains(msg, "tls: internal error") {
		return model.ReasonTLSInternal
	}
	if strings.Contains(msg, "server did not echo the legacy session ID") {
		return model.ReasonTLSSessionID
	}
	if strings.Contains(msg, "unrecognized name") {
		return model.ReasonTLSUnrecognizedName
	}

	// Generic network errors
	if strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "closed by the remote host") {
		return model.ReasonReset
	}

	if strings.Contains(msg, "Application error 0x0") {
		return model.ReasonReset
	}

	if strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "Client.Timeout exceeded") ||
		strings.Contains(msg, "timed out") {
		return model.ReasonTimeout
	}

	return model.ReasonUnknown
}
