package nfqws2

import "fmt"

// KnownFuncs is the closed set of zapret-antidpi.lua desync functions the
// genome is allowed to emit. It is the semantic guard the mutator/galaxy must
// respect: `nfqws2 --dry-run` validates only CLI grammar, not lua symbol
// existence, so a bogus function name would pass dry-run yet fail at runtime.
// Names mirror the functions defined in zapret-antidpi.lua.
var KnownFuncs = map[string]struct{}{
	"drop":           {},
	"send":           {}, // nfqws1: --dup
	"pktmod":         {}, // nfqws1: --orig
	"fake":           {}, // nfqws1: --dpi-desync=fake
	"multisplit":     {}, // nfqws1: split2
	"multidisorder":  {}, // nfqws1: disorder2
	"fakedsplit":     {}, // nfqws1: fakedsplit
	"fakeddisorder":  {}, // nfqws1: fakeddisorder
	"hostfakesplit":  {}, // nfqws1: hostfakesplit
	"tcpseg":         {},
	"syndata":        {}, // nfqws1: --dpi-desync=syndata
	"synack_split":   {}, // nfqws1: --synack-split
	"rst":            {}, // nfqws1: --dpi-desync=rst
	"wsize":          {},
	"wssize":         {}, // nfqws1: --wssize
	"udplen":         {}, // nfqws1: --dpi-desync=udplen
	"dht_dn":         {},
	"http_domcase":   {}, // nfqws1: --domcase
	"http_hostcase":  {}, // nfqws1: --hostcase
	"http_methodeol": {}, // nfqws1: --methodeol
	"http_unixeol":   {},
}

// Common blob names auto-initialized by nfqws2 (see README).
const (
	BlobDefaultTLS  = "fake_default_tls"
	BlobDefaultHTTP = "fake_default_http"
	BlobDefaultQUIC = "fake_default_quic"
)

// Named blobs the worker declares from /app/fake so the genome can reference a
// real google ClientHello as a fake payload or a seqovl overlap pattern — the
// distinctive Zapret-Manager YouTube technique against googlevideo throttling.
const (
	BlobGoogleTLS  = "google_tls"
	BlobGoogleQUIC = "google_quic"
)

// Valid reports the first action whose function is outside KnownFuncs, if any.
// Used as a static correctness guard in tests and before dispatch.
func (s Strategy) Valid() error {
	if len(s.Actions) == 0 {
		return fmt.Errorf("strategy has no actions")
	}
	for _, a := range s.Actions {
		if a.Func == "" {
			return fmt.Errorf("empty action func")
		}
		if _, ok := KnownFuncs[a.Func]; !ok {
			return fmt.Errorf("unknown lua-desync func %q", a.Func)
		}
	}
	return nil
}
