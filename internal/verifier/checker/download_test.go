package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"prikop/internal/model"
	"prikop/internal/verifier/types"
)

// TestCheckDownload locks the P0.1 contract: a body that completes passes, a
// body that stalls mid-transfer is ReasonThrottle (the discord/chaotic failure
// the old HEAD+POST could not see), and a too-small body is inconclusive.
func TestCheckDownload(t *testing.T) {
	const kb = 1024
	cases := []struct {
		name  string
		body  int           // bytes written before returning/stalling
		stall time.Duration // sleep after a partial write (0 = return cleanly)
		want  model.FailureReason
	}{
		{"full body passes", 64 * kb, 0, model.ReasonNone},
		{"stall mid-body is throttle", 8 * kb, 2 * time.Second, model.ReasonThrottle},
		{"tiny body is inconclusive", 1 * kb, 0, model.ReasonSkip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(make([]byte, tc.body))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				if tc.stall > 0 {
					time.Sleep(tc.stall)
				}
			}))
			defer srv.Close()

			client := &http.Client{Timeout: 500 * time.Millisecond}
			tgt := types.Target{URL: srv.URL, DownloadCheck: true}

			res := checkDownload(context.Background(), tgt, client, true)
			if res.reason != tc.want {
				t.Fatalf("reason = %q (%s), want %q", res.reason, res.detail, tc.want)
			}
		})
	}
}

// TestCheckDownloadMinSpeed locks the throughput floor: a body that completes
// but crawls below Target.MinSpeed is still flagged as throttled.
func TestCheckDownloadMinSpeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// 64 KiB dribbled out over ~300ms => ~200 KB/s, under the 1 MB/s floor.
		buf := make([]byte, 4096)
		for range 16 {
			_, _ = w.Write(buf)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	tgt := types.Target{URL: srv.URL, DownloadCheck: true, MinSpeed: 1 << 20} // 1 MB/s

	res := checkDownload(context.Background(), tgt, client, true)
	if res.reason != model.ReasonThrottle {
		t.Fatalf("reason = %q (%s), want throttle for slow download", res.reason, res.detail)
	}
}
