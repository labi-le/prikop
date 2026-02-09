package verifier

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"prikop/internal/model"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
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

type httpClients struct {
	tcp  *http.Client
	quic *http.Client
}

func ExecuteChecks(ctx context.Context, log zerolog.Logger, targets []Target) CheckResult {
	log.Info().Int("target_count", len(targets)).Msg("Verifying group")
	clients := initClients()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed []string
	var failed []string
	errorCounts := make(map[model.FailureReason]int)

	for _, t := range targets {
		wg.Add(1)
		go func(tgt Target) {
			defer wg.Done()

			success, reason := dispatchCheck(ctx, tgt, clients)

			mu.Lock()
			defer mu.Unlock()

			if success {
				passed = append(passed, tgt.URL)
			} else {
				failed = append(failed, tgt.URL)
				if reason != model.ReasonNone {
					errorCounts[reason]++
				}
			}
		}(t)
	}

	wg.Wait()

	return summarizeResults(passed, failed, targets, errorCounts)
}

func initClients() *httpClients {
	tcpTransport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			KeepAlive: HardTimeout,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}

	quicTransport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &httpClients{
		tcp:  &http.Client{Transport: tcpTransport},
		quic: &http.Client{Transport: quicTransport},
	}
}

func dispatchCheck(ctx context.Context, t Target, clients *httpClients) (bool, model.FailureReason) {
	if t.Timeout == 0 {
		t.Timeout = HardTimeout
	}

	switch t.Proto {
	case ProtoSTUN:
		return checkSTUN(ctx, t)
	case ProtoTCP:
		return checkHTTP(ctx, t, clients.tcp)
	case ProtoQUIC:
		return checkHTTP(ctx, t, clients.quic)
	default:
		return false, model.ReasonUnknown
	}
}

func checkHTTP(ctx context.Context, t Target, client *http.Client) (bool, model.FailureReason) {
	// t.Timeout is guaranteed to be set by dispatchCheck
	reqCtx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", t.URL, nil)
	if err != nil {
		return false, model.ReasonUnknown
	}
	req.Header.Set("User-Agent", UserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, analyzeError(err)
	}
	defer resp.Body.Close()

	if !t.IgnoreStatus && (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest) {
		return false, model.ReasonReset
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
			return false, analyzeError(err)
		}
	}

	if readTotal < t.Threshold {
		return false, model.ReasonReset
	}

	// Speed Check
	totalTime := time.Since(start).Seconds()
	if totalTime > 0 {
		speed := float64(readTotal) / totalTime

		minSpeed := t.MinSpeed
		if minSpeed == 0 {
			minSpeed = DefaultMinSpeed // Apply default if not specified to catch obvious throttles
		}

		if speed < minSpeed {
			// Check if we actually downloaded enough to justify a speed check
			if readTotal > MinDataForSpeedCheck {
				return false, model.ReasonThrottle
			}
		}
	}

	return true, model.ReasonNone
}

func checkSTUN(ctx context.Context, t Target) (bool, model.FailureReason) {
	address := strings.TrimPrefix(t.URL, "https://")
	address = strings.TrimPrefix(address, "http://")
	if !strings.Contains(address, ":") {
		address += StunDefaultPort
	}

	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return false, model.ReasonTimeout
	}
	defer conn.Close()

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], StunTypeBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0x0000) // Length
	binary.BigEndian.PutUint32(req[4:8], StunMagicCookie)
	rand.Read(req[8:20]) // Transaction ID

	// Retry logic
	for i := 0; i < StunRetries; i++ {
		if _, err := conn.Write(req); err != nil {
			return false, model.ReasonTimeout
		}

		conn.SetReadDeadline(time.Now().Add(t.Timeout))
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)
		if err == nil && n >= 20 {
			msgType := binary.BigEndian.Uint16(resp[0:2])
			if msgType == StunTypeBindingResponse || msgType == StunTypeBindingSuccess {
				return true, model.ReasonNone
			}
		}
		time.Sleep(StunRetryInterval)
	}

	return false, model.ReasonTimeout
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

	if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "closed by the remote host") {
		return model.ReasonReset
	}

	// QUIC/HTTP3 specific errors
	if strings.Contains(err.Error(), "Application error 0x0") { // H3_NO_ERROR usually treated as clean close, but context matters
		return model.ReasonReset
	}

	return model.ReasonUnknown
}

func summarizeResults(passed, failed []string, targets []Target, errorCounts map[model.FailureReason]int) CheckResult {
	finalReason := model.ReasonNone
	if len(passed) == 0 && len(failed) > 0 {
		if errorCounts[model.ReasonReset] > 0 {
			finalReason = model.ReasonReset
		} else if errorCounts[model.ReasonThrottle] > 0 {
			finalReason = model.ReasonThrottle
		} else if errorCounts[model.ReasonTimeout] > 0 {
			finalReason = model.ReasonTimeout
		} else {
			finalReason = model.ReasonUnknown
		}
	}

	return CheckResult{
		Success:       len(passed) > 0,
		SuccessCount:  len(passed),
		TotalCount:    len(targets),
		PassedUrls:    passed,
		FailedUrls:    failed,
		FailureReason: finalReason,
	}
}
