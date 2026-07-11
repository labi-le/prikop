package checker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"

	"prikop/internal/model"
)

// fakeTimeout implements net.Error with Timeout() == true.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return false }

func TestAnalyzeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want model.FailureReason
	}{
		// --- nil ---
		{"nil", nil, model.ReasonNone},

		// --- type-based ---
		{"context deadline", context.DeadlineExceeded, model.ReasonTimeout},
		{"net timeout", fakeTimeout{}, model.ReasonTimeout},
		{"eof", io.EOF, model.ReasonReset},
		{"unexpected eof", io.ErrUnexpectedEOF, model.ReasonReset},
		{"dns not found", &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}, model.ReasonDNS},
		{"syscall econnreset", os.NewSyscallError("read", syscall.ECONNRESET), model.ReasonReset},
		{"syscall epipe", os.NewSyscallError("write", syscall.EPIPE), model.ReasonReset},
		{
			"opError econnreset",
			&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
			model.ReasonReset,
		},

		// --- unwrapping url.Error ---
		{
			"url error wraps deadline",
			&url.Error{Op: "Get", URL: "https://x", Err: context.DeadlineExceeded},
			model.ReasonTimeout,
		},
		{
			"url error wraps tls handshake string",
			&url.Error{Op: "Get", URL: "https://x", Err: errors.New("tls: handshake failure")},
			model.ReasonTLSHandshake,
		},

		// --- string-based TLS interventions ---
		{"alpn", errors.New("tls: server advertised unrequested ALPN extension"), model.ReasonTLSALPN},
		{"oversized", errors.New("tls: oversized record received of length 20597"), model.ReasonTLSOversized},
		{"not tls", errors.New("first record does not look like a TLS handshake"), model.ReasonTLSNotTLS},
		{"handshake failure", errors.New("remote error: tls: handshake failure"), model.ReasonTLSHandshake},
		{"unexpected message", errors.New("tls: unexpected message"), model.ReasonTLSAlertUnexpected},
		{"bad record mac", errors.New("local error: tls: bad record MAC"), model.ReasonTLSBadMAC},

		// --- string-based generic ---
		{"connection reset string", errors.New("read tcp 1.2.3.4:443: connection reset by peer"), model.ReasonReset},
		{"quic app error", errors.New("Application error 0x0 (remote)"), model.ReasonReset},
		{"client timeout string", errors.New("Client.Timeout exceeded while awaiting headers"), model.ReasonTimeout},

		// --- fallthrough ---
		{"unknown", errors.New("something completely unrelated"), model.ReasonUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzeError(tc.err); got != tc.want {
				t.Fatalf("AnalyzeError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
