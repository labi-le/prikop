package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"prikop/internal/model"
	"prikop/internal/targets"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func RunWorkerMode(strategy string, groupName string) {
	log.SetOutput(os.Stderr)
	if strategy == "" {
		fatalJSON("No strategy provided in args")
	}

	cmds := [][]string{
		{"iptables", "-t", "mangle", "-F"},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
		// Add High ports for Discord UDP
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "50000:65535", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fatalJSON(fmt.Sprintf("iptables error: %v | out: %s", err, string(out)))
		}
	}

	nfqwsArgs := strings.Fields(fmt.Sprintf("--qnum=%s %s", model.QueueNum, strategy))
	cmd := exec.Command("nfqws", nfqwsArgs...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		fatalJSON(fmt.Sprintf("nfqws start failed: %v", err))
	}

	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-doneCh:
		fatalJSON(fmt.Sprintf("nfqws crashed immediately: %v | Logs: %s", err, stderrBuf.String()))
	default:
	}

	tcpClient := &http.Client{
		Timeout: model.CheckTimeout + 1*time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:   false,
			TLSHandshakeTimeout: 3 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	// CRITICAL FIX: Skip verification for QUIC to avoid cert errors on fake packets
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	quicClient := &http.Client{
		Timeout:   model.CheckTimeout + 1*time.Second,
		Transport: h3Transport,
	}

	var wg sync.WaitGroup
	var successCount int32
	var totalChecks int32
	sem := make(chan struct{}, 12)

	targetList := targets.GetGroup(groupName)
	if len(targetList) == 0 {
		fatalJSON(fmt.Sprintf("No targets found for group: %s", groupName))
	}

	for _, t := range targetList {
		for i := 0; i < t.Times; i++ {
			wg.Add(1)
			totalChecks++
			targetURL := t.URL
			if !strings.Contains(targetURL, "t=") {
				sep := "?"
				if strings.Contains(targetURL, "?") {
					sep = "&"
				}
				targetURL += fmt.Sprintf("%st=%d", sep, time.Now().UnixNano())
			}

			threshold := t.Threshold
			if threshold == 0 {
				threshold = model.DefaultBinaryThreshold
			}

			isQuic := t.Proto == "quic"
			ignoreStatus := t.IgnoreStatus

			go func(u string, thresh int, quic, ignoreStat bool) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				select {
				case <-doneCh:
					return
				default:
				}

				ctx, cancel := context.WithTimeout(context.Background(), model.CheckTimeout)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				if err != nil {
					return
				}
				req.Header.Set("Cache-Control", "no-store")
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

				var client *http.Client
				if quic {
					client = quicClient
				} else {
					client = tcpClient
				}

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				if !ignoreStat && (resp.StatusCode < 200 || resp.StatusCode >= 400) {
					return
				}

				buf := make([]byte, 8192)
				var received int
				var ok bool
				for {
					n, rErr := resp.Body.Read(buf)
					received += n
					if received >= thresh {
						ok = true
						break
					}
					if rErr != nil {
						break
					}
				}
				if ok {
					atomic.AddInt32(&successCount, 1)
				}
			}(targetURL, threshold, isQuic, ignoreStatus)
		}
	}
	wg.Wait()

	select {
	case err := <-doneCh:
		fatalJSON(fmt.Sprintf("nfqws crashed: %v | Logs: %s", err, stderrBuf.String()))
	default:
	}

	finalSuccess := int(atomic.LoadInt32(&successCount))
	res := model.WorkerResult{
		Success:      finalSuccess > 0,
		Code:         200,
		SuccessCount: finalSuccess,
		TotalCount:   int(totalChecks),
	}
	if finalSuccess == 0 {
		res.Error = "No targets passed"
	}
	printJSON(res)
}

func printJSON(res model.WorkerResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(res)
}

func fatalJSON(msg string) {
	printJSON(model.WorkerResult{Success: false, Error: msg})
	os.Exit(1)
}
