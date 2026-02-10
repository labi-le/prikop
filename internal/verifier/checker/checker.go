package checker

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"prikop/internal/model"
	"prikop/internal/verifier/types"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
)

const (
	HardTimeout = 5 * time.Second
	UserAgent   = "Mozilla"
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
	tcp  *http.Client
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

// - не следует редиректам
// - валидация сертификатов включена
func initClients() *httpClients {
	noRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tcpTransport := &http.Transport{
		TLSClientConfig:       &tls.Config{},
		TLSHandshakeTimeout:   HardTimeout,
		ResponseHeaderTimeout: HardTimeout,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: HardTimeout,
		}).DialContext,
	}

	quicTransport := &http3.Transport{
		TLSClientConfig: &tls.Config{},
	}

	return &httpClients{
		tcp: &http.Client{
			Transport:     tcpTransport,
			CheckRedirect: noRedirect,
		},
		quic: &http.Client{
			Transport:     quicTransport,
			CheckRedirect: noRedirect,
		},
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
		return checkHTTP(ctx, t, clients.tcp)
	case types.ProtoQUIC:
		return checkHTTP(ctx, t, clients.quic)
	default:
		return failResult(model.ReasonUnknown, "unsupported protocol")
	}
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
		return failResult(AnalyzeError(err), err.Error())
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
			return failResult(AnalyzeError(err), fmt.Sprintf("body read: %s (got %d/%d bytes)", err, readTotal, t.Threshold))
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
