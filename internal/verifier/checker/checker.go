package checker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"prikop/internal/model"
	"prikop/internal/verifier/types"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
)

const (
	// JS: let TIMEOUT_MS = 15000;
	DefaultTimeout = 15 * time.Second
	// JS: const DPI_THR_BYTES = 64 * 1024;
	PostPayloadSize = 64 * 1024

	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	StunDefaultPort         = ":3478"
	StunRetries             = 3
	StunRetryInterval       = 200 * time.Millisecond
	StunTypeBindingRequest  = 0x0001
	StunMagicCookie         = 0x2112A442
	StunTypeBindingResponse = 0x0101
	StunTypeBindingSuccess  = 0x0111
)

// reasonSkip marks an inconclusive result — not a pass, not a hard failure.
// Corresponds to JS "skip", "probably detected", "possible detected", "unlikely".
const reasonSkip model.FailureReason = "skip"

type checkResult struct {
	reason model.FailureReason
	detail string
}

var okResult = checkResult{reason: model.ReasonNone}
var skipResult = checkResult{reason: reasonSkip}

func failResult(reason model.FailureReason, detail string) checkResult {
	return checkResult{reason: reason, detail: detail}
}

func ExecuteChecks(ctx context.Context, log zerolog.Logger, targets []types.Target, cidrPath string) types.CheckResult {
	log.Info().Int("target_count", len(targets)).Str("cidr_file", cidrPath).Msg("Verifying group (TCP 16-20 Logic)")

	var cidrList []*net.IPNet
	if cidrPath != "" {
		if list, err := LoadCIDRs(cidrPath); err != nil {
			log.Warn().Err(err).Msg("Failed to load CIDRs for validation")
		} else {
			cidrList = list
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed []string
	var failed []string
	errorCounts := make(map[model.FailureReason]int)

	for _, t := range targets {
		wg.Add(1)
		go func(tgt types.Target) {
			defer wg.Done()

			// CIDR Validation
			if len(cidrList) > 0 {
				if err := ValidateIP(tgt.URL, cidrList); err != nil {
					mu.Lock()
					failed = append(failed, tgt.URL)
					errorCounts[model.ReasonCIDR]++
					log.Error().Str("url", tgt.URL).Err(err).Msg("Target excluded: IP not in CIDR")
					mu.Unlock()
					return
				}
			}

			start := time.Now()
			res := dispatchCheck(ctx, tgt)
			elapsed := time.Since(start)

			mu.Lock()
			defer mu.Unlock()

			if res.reason == model.ReasonNone {
				passed = append(passed, tgt.URL)
			} else if res.reason == reasonSkip {
				// Inconclusive — JS "skip/probably/possible/unlikely detected".
				// Do not count as pass or fail; just log.
				log.Debug().
					Str("url", tgt.URL).
					Str("proto", tgt.Proto.String()).
					Str("detail", res.detail).
					Dur("elapsed", elapsed).
					Msg("Target result inconclusive (skip)")
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

func LoadCIDRs(path string) ([]*net.IPNet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var networks []*net.IPNet
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err == nil {
			networks = append(networks, ipnet)
		}
	}
	return networks, nil
}

func ValidateIP(rawURL string, networks []*net.IPNet) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		for _, netw := range networks {
			if netw.Contains(ip) {
				return nil
			}
		}
	}

	return fmt.Errorf("ip %v not in cidr ranges", ips)
}

func createHttpClient(proto types.Protocol, timeout time.Duration) *http.Client {
	if proto == types.ProtoQUIC {
		return &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: timeout,
		}
	}

	// TCP Client — keepalive: false, redirect: follow (matches JS fetch defaults)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			DisableCompression:    true,
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   -1,
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		Timeout: timeout,
	}
}

func dispatchCheck(ctx context.Context, t types.Target) checkResult {
	if t.Timeout == 0 {
		t.Timeout = DefaultTimeout
	}

	switch t.Proto {
	case types.ProtoSTUN:
		return checkSTUN(ctx, t)
	case types.ProtoTCP, types.ProtoQUIC:
		client := createHttpClient(t.Proto, t.Timeout)
		return checkHTTPSequence(ctx, t, client)
	default:
		return failResult(model.ReasonUnknown, "unsupported protocol")
	}
}

// checkHTTPSequence implements the 2-step DPI detection logic from main.js:
//
// Step 1 — HEAD (liveness check):
//   - HEAD timeout (AbortError in JS)  → skip entirely (target dead/unreachable)
//   - HEAD instant error (other JS error) → alive=false, still try POST
//   - HEAD success                      → alive=true, try POST
//
// Step 2 — POST 64 KiB (DPI check):
//   - POST success                      → not detected ✅ (PASS)
//   - POST timeout + alive              → detected ❗ (FAIL — DPI throttling)
//   - POST timeout + !alive             → probably detected ⚠️ (SKIP — inconclusive)
//   - POST instant error (any alive)    → possible/unlikely detected ⚠️ (SKIP — inconclusive)
func checkHTTPSequence(ctx context.Context, t types.Target, client *http.Client) checkResult {
	// --- Step 1: Liveness Check (HEAD) ---
	aliveURL := getUniqueURL(t.URL)
	reqHead, err := http.NewRequestWithContext(ctx, "HEAD", aliveURL, nil)
	if err != nil {
		return failResult(model.ReasonUnknown, err.Error())
	}
	setCommonHeaders(reqHead)

	var alive bool
	respHead, err := client.Do(reqHead)
	if err != nil {
		reason := AnalyzeError(err)
		if reason == model.ReasonTimeout {
			// JS: AbortError on HEAD → alive=false, possibleAlive=false → skip
			return skipResult
		}
		// JS: other error on HEAD → alive=false, possibleAlive=true → continue to POST
		alive = false
	} else {
		respHead.Body.Close()
		alive = true
	}

	// --- Step 2: DPI Check (POST 64 KiB) ---
	dpiURL := getUniqueURL(t.URL)

	payload := make([]byte, PostPayloadSize)
	if _, err := rand.Read(payload); err != nil {
		return failResult(model.ReasonUnknown, "failed to gen payload")
	}

	reqPost, err := http.NewRequestWithContext(ctx, "POST", dpiURL, bytes.NewReader(payload))
	if err != nil {
		return failResult(model.ReasonUnknown, err.Error())
	}
	setCommonHeaders(reqPost)
	reqPost.ContentLength = int64(PostPayloadSize)
	reqPost.Header.Set("Content-Type", "application/octet-stream")

	startPost := time.Now()
	respPost, err := client.Do(reqPost)
	if err != nil {
		reason := AnalyzeError(err)
		if reason == model.ReasonTimeout {
			if alive {
				// JS: HEAD ok + POST timeout → detected ❗ (FAIL)
				return failResult(model.ReasonThrottle, fmt.Sprintf("POST timed out after %v (DPI detected)", time.Since(startPost)))
			}
			// JS: HEAD instant error + POST timeout → probably detected ⚠️ (SKIP)
			return skipResult
		}
		// JS: POST instant error (any alive value) → possible/unlikely detected ⚠️ (SKIP)
		return skipResult
	}
	defer respPost.Body.Close()

	// Drain body so the connection is properly closed
	io.Copy(io.Discard, respPost.Body)

	// JS: POST completes without error → not detected ✅ (PASS)
	return okResult
}

func getUniqueURL(base string) string {
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	// JS: `${url}${sep}t=${Math.random()}`
	return fmt.Sprintf("%s%st=%d", base, separator, time.Now().UnixNano())
}

func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	// JS: cache: "no-store"
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
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
