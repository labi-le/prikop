package checker

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"prikop/internal/model"
	"prikop/internal/verifier/types"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
)

const (
	HardTimeout = 5 * time.Second
	UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	// DefaultMinSpeed defines a sane default for throttling detection (e.g., 10KB/s)
	DefaultMinSpeed = 10 * 1024.0

	HttpBufferSize       = 4096
	MinDataForSpeedCheck = 1024
	StunDefaultPort      = ":3478"
	StunRetries          = 3
	StunRetryInterval    = 200 * time.Millisecond

	StunTypeBindingRequest  = 0x0001
	StunMagicCookie         = 0x2112A442
	StunTypeBindingResponse = 0x0101
	StunTypeBindingSuccess  = 0x0111
)

type checkResult struct {
	reason model.FailureReason
	detail string
}

var okResult = checkResult{reason: model.ReasonNone}

func failResult(reason model.FailureReason, detail string) checkResult {
	return checkResult{reason: reason, detail: detail}
}

type httpClients struct {
	tcp  *fasthttp.Client
	quic *http.Client
}

var (
	sharedClients *httpClients
	clientsOnce   sync.Once
)

func getClients() *httpClients {
	clientsOnce.Do(func() {
		sharedClients = initClients()
	})
	return sharedClients
}

func ExecuteChecks(ctx context.Context, log zerolog.Logger, targets []types.Target) types.CheckResult {
	log.Info().Int("target_count", len(targets)).Msg("Verifying group")
	clients := getClients()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed []string
	var failed []string
	errorCounts := make(map[model.FailureReason]int)

	for _, t := range targets {
		wg.Add(1)
		go func(tgt types.Target) {
			defer wg.Done()

			start := time.Now()
			res := dispatchCheck(ctx, tgt, clients)
			elapsed := time.Since(start)

			mu.Lock()
			defer mu.Unlock()

			if res.reason == model.ReasonNone {
				passed = append(passed, tgt.URL)
			} else {
				failed = append(failed, tgt.URL)
				errorCounts[res.reason]++
				log.Warn().
					Str("url", tgt.URL).
					Str("proto", tgt.Proto.String()).
					Str("reason", string(res.reason)).
					Str("detail", res.detail).
					Dur("elapsed", elapsed).
					Send()
			}
		}(t)
	}

	wg.Wait()

	result := summarizeResults(passed, failed, targets, errorCounts)

	log.Info().
		Bool("success", result.Success).
		Int("passed", result.SuccessCount).
		Int("failed", len(result.FailedUrls)).
		Int("total", result.TotalCount).
		Str("failure_reason", string(result.FailureReason)).
		Msg("Check summary")

	return result
}

func initClients() *httpClients {
	quicTransport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &httpClients{
		tcp: &fasthttp.Client{
			TLSConfig:                     &tls.Config{InsecureSkipVerify: true},
			MaxConnsPerHost:               64,
			ReadTimeout:                   HardTimeout,
			WriteTimeout:                  HardTimeout,
			MaxResponseBodySize:           128 * 1024,
			DisableHeaderNamesNormalizing: true,
		},
		quic: &http.Client{Transport: quicTransport},
	}
}

func dispatchCheck(ctx context.Context, t types.Target, clients *httpClients) checkResult {
	if t.Timeout == 0 {
		t.Timeout = HardTimeout
	}

	switch t.Proto {
	case types.ProtoSTUN:
		return checkSTUN(ctx, t)
	case types.ProtoTCP:
		return checkFastHTTP(t, clients.tcp)
	case types.ProtoQUIC:
		return checkHTTP(ctx, t, clients.quic)
	default:
		return failResult(model.ReasonUnknown, "unsupported protocol")
	}
}

func checkFastHTTP(t types.Target, client *fasthttp.Client) checkResult {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(t.URL)
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", UserAgent)

	start := time.Now()
	err := client.DoTimeout(req, resp, t.Timeout)
	if err != nil {
		if errors.Is(err, fasthttp.ErrBodyTooLarge) {
			// Body exceeded MaxResponseBodySize — connection works, data flows.
			return okResult
		}
		return failResult(analyzeFasthttpError(err), err.Error())
	}

	statusCode := resp.StatusCode()
	if !t.IgnoreStatus && (statusCode < fasthttp.StatusOK || statusCode >= fasthttp.StatusBadRequest) {
		return failResult(model.ReasonReset, fmt.Sprintf("HTTP %d", statusCode))
	}

	body := resp.Body()
	readTotal := len(body)

	if readTotal < t.Threshold {
		return failResult(model.ReasonReset, fmt.Sprintf("short body: %d/%d bytes", readTotal, t.Threshold))
	}

	totalTime := time.Since(start).Seconds()
	if totalTime > 0 {
		speed := float64(readTotal) / totalTime

		minSpeed := t.MinSpeed
		if minSpeed == 0 {
			minSpeed = DefaultMinSpeed
		}

		if speed < minSpeed && readTotal > MinDataForSpeedCheck {
			return failResult(model.ReasonThrottle, fmt.Sprintf("%.1f KB/s (min %.1f KB/s)", speed/1024, minSpeed/1024))
		}
	}

	return okResult
}

func analyzeFasthttpError(err error) model.FailureReason {
	if err == nil {
		return model.ReasonNone
	}

	if errors.Is(err, fasthttp.ErrTimeout) {
		return model.ReasonTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ReasonTimeout
	}

	if errors.Is(err, fasthttp.ErrConnectionClosed) {
		return model.ReasonReset
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return model.ReasonReset
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

	// 2. Парсинг строковых сообщений (String Matching)
	// Это необходимо, так как crypto/tls возвращает простые errors.New()
	msg := err.Error()

	// --- TLS: Вмешательство DPI (Specific Interventions) ---

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
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
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

	// Нарушение порядка сообщений (State Machine Error) - бывает из-за --dpi-desync=disorder
	if strings.Contains(msg, "remote error: unexpected message") {
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

	if strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused") {
		return model.ReasonReset
	}

	if strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "Client.Timeout exceeded") ||
		strings.Contains(msg, "timed out") {
		return model.ReasonTimeout
	}

	return analyzeError(err) // Используем ваш базовый анализатор как fallback
}

func checkHTTP(ctx context.Context, t types.Target, client *http.Client) checkResult {
	reqCtx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", t.URL, nil)
	if err != nil {
		return failResult(model.ReasonUnknown, err.Error())
	}
	req.Header.Set("User-Agent", UserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		reason := analyzeError(err)
		return failResult(reason, err.Error())
	}
	defer resp.Body.Close()

	if !t.IgnoreStatus && (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest) {
		return failResult(model.ReasonReset, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	// Data Transfer Phase
	buf := make([]byte, HttpBufferSize)
	readTotal := 0

	for readTotal < t.Threshold {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			readTotal += n
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			reason := analyzeError(err)
			return failResult(reason, fmt.Sprintf("body read: %s (got %d/%d bytes)", err, readTotal, t.Threshold))
		}
	}

	if readTotal < t.Threshold {
		return failResult(model.ReasonReset, fmt.Sprintf("short body: %d/%d bytes", readTotal, t.Threshold))
	}

	// Speed Check
	totalTime := time.Since(start).Seconds()
	if totalTime > 0 {
		speed := float64(readTotal) / totalTime

		minSpeed := t.MinSpeed
		if minSpeed == 0 {
			minSpeed = DefaultMinSpeed
		}

		if speed < minSpeed && readTotal > MinDataForSpeedCheck {
			return failResult(model.ReasonThrottle, fmt.Sprintf("%.1f KB/s (min %.1f KB/s)", speed/1024, minSpeed/1024))
		}
	}

	return okResult
}

func checkSTUN(ctx context.Context, t types.Target) checkResult {
	address := strings.TrimPrefix(t.URL, "https://")
	address = strings.TrimPrefix(address, "http://")
	if !strings.Contains(address, ":") {
		address += StunDefaultPort
	}

	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return failResult(model.ReasonTimeout, fmt.Sprintf("dial: %s", err))
	}
	defer conn.Close()

	reqBuf := make([]byte, 20)
	binary.BigEndian.PutUint16(reqBuf[0:2], StunTypeBindingRequest)
	binary.BigEndian.PutUint16(reqBuf[2:4], 0x0000)
	binary.BigEndian.PutUint32(reqBuf[4:8], StunMagicCookie)
	rand.Read(reqBuf[8:20])

	var lastErr error
	for i := 0; i < StunRetries; i++ {
		if _, err := conn.Write(reqBuf); err != nil {
			return failResult(model.ReasonTimeout, fmt.Sprintf("write: %s", err))
		}

		conn.SetReadDeadline(time.Now().Add(t.Timeout))
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		if err != nil {
			lastErr = err
		} else if n >= 20 {
			msgType := binary.BigEndian.Uint16(resp[0:2])
			if msgType == StunTypeBindingResponse || msgType == StunTypeBindingSuccess {
				return okResult
			}
			lastErr = fmt.Errorf("unexpected STUN type 0x%04x", msgType)
		}
		time.Sleep(StunRetryInterval)
	}

	detail := fmt.Sprintf("no response after %d retries", StunRetries)
	if lastErr != nil {
		detail = fmt.Sprintf("%s: %s", detail, lastErr)
	}
	return failResult(model.ReasonTimeout, detail)
}

func analyzeError(err error) model.FailureReason {
	if err == nil {
		return model.ReasonNone
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.ReasonTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ReasonTimeout
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

	errMsg := err.Error()
	if strings.Contains(errMsg, "reset") || strings.Contains(errMsg, "closed by the remote host") {
		return model.ReasonReset
	}

	if strings.Contains(errMsg, "Application error 0x0") {
		return model.ReasonReset
	}

	return model.ReasonUnknown
}

func summarizeResults(passed, failed []string, targets []types.Target, errorCounts map[model.FailureReason]int) types.CheckResult {
	finalReason := model.ReasonNone
	if len(passed) == 0 && len(failed) > 0 {
		if errorCounts[model.ReasonReset] > 0 {
			finalReason = model.ReasonReset
		} else if errorCounts[model.ReasonThrottle] > 0 {
			finalReason = model.ReasonThrottle
		} else if errorCounts[model.ReasonTimeout] > 0 {
			finalReason = model.ReasonTimeout
		} else {
			// Pick the most frequent TLS sub-reason, or unknown
			finalReason = model.ReasonUnknown
			maxCount := 0
			for reason, count := range errorCounts {
				if reason.IsTLS() && count > maxCount {
					finalReason = reason
					maxCount = count
				}
			}
		}
	}

	details := fmt.Sprintf("%d/%d passed", len(passed), len(targets))

	return types.CheckResult{
		Success:       len(passed) > 0,
		SuccessCount:  len(passed),
		TotalCount:    len(targets),
		Details:       details,
		PassedUrls:    passed,
		FailedUrls:    failed,
		FailureReason: finalReason,
	}
}
