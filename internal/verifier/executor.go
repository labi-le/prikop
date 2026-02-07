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
)

const (
	HardTimeout = 5 * time.Second
	UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

func ExecuteChecks(ctx context.Context, targets []Target) CheckResult {
	tcpTransport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   HardTimeout,
		ResponseHeaderTimeout: HardTimeout,
		DialContext: (&net.Dialer{
			Timeout: HardTimeout,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}

	quicTransport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	tcpClient := &http.Client{Timeout: HardTimeout, Transport: tcpTransport}
	quicClient := &http.Client{Timeout: HardTimeout, Transport: quicTransport}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed []string
	var failed []string

	errorCounts := make(map[model.FailureReason]int)

	for _, t := range targets {
		wg.Add(1)

		go func(tgt Target) {
			defer wg.Done()
			success := false
			var failReason = model.ReasonNone

			defer func() {
				mu.Lock()
				if success {
					passed = append(passed, tgt.URL)
				} else {
					failed = append(failed, tgt.URL)
					if failReason != model.ReasonNone {
						errorCounts[failReason]++
					}
				}
				mu.Unlock()
			}()

			if tgt.Proto == "stun" {
				if checkSTUN(ctx, tgt.URL) {
					success = true
				} else {
					failReason = model.ReasonTimeout
				}
				return
			}

			cli := tcpClient
			if tgt.Proto == "quic" {
				cli = quicClient
			}

			reqCtx, cancel := context.WithTimeout(ctx, HardTimeout)
			defer cancel()

			req, err := http.NewRequestWithContext(reqCtx, "GET", tgt.URL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", UserAgent)

			resp, err := cli.Do(req)
			if err != nil {
				failReason = analyzeError(err)
				return
			}
			defer resp.Body.Close()

			if !tgt.IgnoreStatus && (resp.StatusCode < 200 || resp.StatusCode >= 400) {
				failReason = model.ReasonReset
				return
			}

			buf := make([]byte, 4096)
			readTotal := 0
			for readTotal < tgt.Threshold {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					readTotal += n
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					failReason = analyzeError(err)
					return
				}
			}

			if readTotal >= tgt.Threshold {
				success = true
			} else {
				failReason = model.ReasonReset
			}
		}(t)
	}

	wg.Wait()

	finalReason := model.ReasonNone
	if len(passed) == 0 && len(failed) > 0 {
		if errorCounts[model.ReasonReset] > 0 {
			finalReason = model.ReasonReset
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

// analyzeError пытается классифицировать ошибку сети
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

	return model.ReasonUnknown
}

func checkSTUN(ctx context.Context, address string) bool {
	address = strings.TrimPrefix(address, "https://")
	address = strings.TrimPrefix(address, "http://")

	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return false
	}
	defer conn.Close()

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)     // Type
	binary.BigEndian.PutUint16(req[2:4], 0x0000)     // Length
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442) // Magic Cookie
	rand.Read(req[8:20])                             // Transaction ID

	if _, err := conn.Write(req); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return false
	}

	if n < 20 {
		return false
	}

	msgType := binary.BigEndian.Uint16(resp[0:2])
	return msgType == 0x0101 || msgType == 0x0111
}
