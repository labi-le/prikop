package verifier

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type GeneralVerifier struct {
	Mode string
}

func (v *GeneralVerifier) Name() string { return "General Verifier (HTML Logic)" }

func (v *GeneralVerifier) Run(ctx context.Context) CheckResult {
	const Threshold = 64 * 1024

	targets := []Target{
		// US.CF-01
		{URL: "https://img.wzstats.gg/cleaver/gunFullDisplay", Threshold: Threshold, IgnoreStatus: true},
		// US.CF-02
		{URL: "https://genshin.jmp.blue/characters/all#", Threshold: Threshold, IgnoreStatus: true},
		// US.CF-03
		{URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: Threshold, IgnoreStatus: true},
		// US.CF-04
		{URL: "https://www.bigcartel.com/", Threshold: Threshold, IgnoreStatus: true},

		// US.CF-02
		{URL: "https://genshin.jmp.blue/characters/all#", Threshold: Threshold, IgnoreStatus: true},
		// US.CF-03
		{URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: Threshold, IgnoreStatus: true},

		// US.CF-02
		{URL: "https://genshin.jmp.blue/characters/all#", Threshold: Threshold, IgnoreStatus: true},
		// US.CF-03
		{URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31", Threshold: Threshold, IgnoreStatus: true},

		// US.DO-01 (times: 2)
		{URL: "https://genderize.io/", Threshold: Threshold, IgnoreStatus: true},
		{URL: "https://genderize.io/", Threshold: Threshold, IgnoreStatus: true},
		// DE.HE-01
		{URL: "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp", Threshold: Threshold, IgnoreStatus: true},
		// DE.HE-02
		{URL: "https://accesorioscelular.com/tienda/css/plugins.css", Threshold: Threshold, IgnoreStatus: true},
		// FI.HE-01
		{URL: "https://251b5cd9.nip.io/1MB.bin", Threshold: Threshold, IgnoreStatus: true},
		// FI.HE-02
		{URL: "https://nioges.com/libs/fontawesome/webfonts/fa-solid-900.woff2", Threshold: Threshold, IgnoreStatus: true},
		// FI.HE-03
		{URL: "https://5fd8bdae.nip.io/1MB.bin", Threshold: Threshold, IgnoreStatus: true},
		// FI.HE-04
		{URL: "https://5fd8bca5.nip.io/1MB.bin", Threshold: Threshold, IgnoreStatus: true},
		// FR.OVH-01
		{URL: "https://eu.api.ovh.com/console/rapidoc-min.js", Threshold: Threshold, IgnoreStatus: true},
		// FR.OVH-02
		{URL: "https://ovh.sfx.ovh/10M.bin", Threshold: Threshold, IgnoreStatus: true},
		// SE.OR-01
		{URL: "https://oracle.sfx.ovh/10M.bin", Threshold: Threshold, IgnoreStatus: true},
		// DE.AWS-01
		{URL: "https://www.getscope.com/assets/fonts/fa-solid-900.woff2", Threshold: Threshold, IgnoreStatus: true},
		// US.AWS-01
		{URL: "https://corp.kaltura.com/wp-content/cache/min/1/wp-content/themes/airfleet/dist/styles/theme.css", Threshold: Threshold, IgnoreStatus: true},
		// US.GC-01
		{URL: "https://api.usercentrics.eu/gvl/v3/en.json", Threshold: Threshold, IgnoreStatus: true},
		// US.FST-01
		{URL: "https://www.jetblue.com/footer/footer-element-es2015.js", Threshold: Threshold, IgnoreStatus: true},
		// CA.FST-01
		{URL: "https://ssl.p.jwpcdn.com/player/v/8.40.5/bidding.js", Threshold: Threshold, IgnoreStatus: true},
		// US.AKM-01
		{URL: "https://www.roxio.com/static/roxio/images/products/creator/nxt9/call-action-footer-bg.jpg", Threshold: Threshold, IgnoreStatus: true},
		// PL.AKM-01
		{URL: "https://media-assets.stryker.com/is/image/stryker/gateway_1?$max_width_1410$", Threshold: Threshold, IgnoreStatus: true},
		// US.CDN77-01
		{URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg", Threshold: Threshold, IgnoreStatus: true},
		// FR.CNTB-01
		{URL: "https://xdmarineshop.gr/index.php?route=index", Threshold: Threshold, IgnoreStatus: true},
		// NL.SW-01
		{URL: "https://www.velivole.fr/img/header.jpg", Threshold: Threshold, IgnoreStatus: true},
		// US.CNST-01
		{URL: "https://cdn.xuansiwei.com/common/lib/font-awesome/4.7.0/fontawesome-webfont.woff2?v=4.7.0", Threshold: Threshold, IgnoreStatus: true},
	}
	return runParallelChecks(ctx, targets)
}

// runParallelChecks replicates index.html fetch logic
func runParallelChecks(ctx context.Context, targets []Target) CheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var passed []string
	var failed []string

	// HTML Checker Logic: "TIMEOUT_MS = 5000"
	// This includes connection time + read time.
	const HardTimeout = 5 * time.Second

	// Browser User-Agent (HTML checker runs in browser)
	const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// Transports with InsecureSkipVerify (DPI bypass check, not security check)
	tcpTransport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   HardTimeout,
		ResponseHeaderTimeout: HardTimeout,
		DialContext: (&net.Dialer{
			Timeout: HardTimeout,
		}).DialContext,
	}

	quicTransport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	tcpClient := &http.Client{Timeout: HardTimeout, Transport: tcpTransport}
	quicClient := &http.Client{Timeout: HardTimeout, Transport: quicTransport}

	for _, t := range targets {
		wg.Add(1)

		go func(tgt Target) {
			defer wg.Done()
			success := false

			defer func() {
				mu.Lock()
				if success {
					passed = append(passed, tgt.URL)
				} else {
					failed = append(failed, tgt.URL)
				}
				mu.Unlock()
			}()

			// STUN Check (Not present in general.html but kept for compatibility with other modes)
			if tgt.Proto == "stun" {
				if checkSTUN(ctx, tgt.URL) {
					success = true
				}
				return
			}

			// Create a hard timeout context for this specific request, mimicking AbortController(5000)
			reqCtx, cancel := context.WithTimeout(ctx, HardTimeout)
			defer cancel()

			cli := tcpClient
			if tgt.Proto == "quic" {
				cli = quicClient
			}

			req, err := http.NewRequestWithContext(reqCtx, "GET", tgt.URL, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", UserAgent)
			// IMPORTANT: Removed Range header to strictly match fetch() behavior in index.html

			resp, err := cli.Do(req)
			if err != nil {
				// Connection failure or timeout during handshake
				return
			}
			defer resp.Body.Close()

			// HTML Checker Logic: Log HTTP status but continue reading unless it's a network error.
			// However, for counting "Success", we generally expect 200 unless IgnoreStatus is true.
			// The provided logic implies we just need to read T bytes.
			if !tgt.IgnoreStatus && (resp.StatusCode < 200 || resp.StatusCode >= 400) {
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
						// Stream complete (Early complete)
						break
					}
					// Read error or timeout
					return
				}
			}

			// Success if we read enough data OR if we read everything provided (even if less than T, usually implies success if no error occurred)
			// But sticking to strict threshold logic:
			if readTotal >= tgt.Threshold {
				success = true
			}
		}(t)
	}

	wg.Wait()

	return CheckResult{
		Success:      len(passed) > 0, // Success if at least one passes
		SuccessCount: len(passed),
		TotalCount:   len(targets),
		PassedUrls:   passed,
		FailedUrls:   failed,
	}
}

// checkSTUN sends a Binding Request and expects a Binding Response
func checkSTUN(ctx context.Context, address string) bool {
	// Clean address (remove https:// if present, though verifier should pass host:port)
	address = strings.TrimPrefix(address, "https://")
	address = strings.TrimPrefix(address, "http://")

	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return false
	}
	defer conn.Close()

	// STUN Binding Request:
	// Type: 0x0001
	// Length: 0x0000
	// Magic Cookie: 0x2112A442
	// Transaction ID: 12 random bytes
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

	// Verify header length
	if n < 20 {
		return false
	}

	// Check Type: 0x0101 (Binding Success Response) or 0x0111 (Binding Error)
	// We accept both as sign of connectivity bypassing DPI blocks
	msgType := binary.BigEndian.Uint16(resp[0:2])
	return msgType == 0x0101 || msgType == 0x0111
}
