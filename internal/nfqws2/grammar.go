// Package nfqws2 models the nfqws2 (zapret2) strategy genome.
//
// Unlike nfqws1, nfqws2 has no built-in "--dpi-desync" engine: every desync
// action is a Lua function invoked per packet via "--lua-desync=func:params".
// A strategy is therefore a profile-level filter set plus an ORDERED list of
// action instances. This maps naturally onto the evolutionary search: a gene is
// an action instance; crossover swaps instance sub-lists; mutation tweaks an
// instance's params or adds/removes/reorders instances.
//
// The emitted args are validated against the real binary with `nfqws2 --dry-run`.
package nfqws2

import "strings"

// Param is a single "key" or "key=value" argument of a lua-desync action.
// An empty Value renders as a bare boolean flag (":key").
type Param struct {
	Key   string
	Value string
}

// P builds a key=value param.
func P(key, value string) Param { return Param{Key: key, Value: value} }

// Flag builds a valueless boolean param.
func Flag(key string) Param { return Param{Key: key} }

// Action is one "--lua-desync=Func[:param...]" instance.
type Action struct {
	Func   string
	Params []Param
}

// Filter is the profile-level selection applied to the actions that follow it.
type Filter struct {
	TCP     string   // --filter-tcp (e.g. "80,443")
	UDP     string   // --filter-udp (e.g. "443")
	L7      []string // --filter-l7 (tls, http, quic, ...)
	Payload []string // --payload (tls_client_hello, http_req, quic_initial, ...)
}

// Strategy is the nfqws2 genome: a filter profile plus ordered action instances.
type Strategy struct {
	Filter  Filter
	Actions []Action
}

// String renders the strategy as a single command-line fragment.
func (s Strategy) String() string {
	return strings.Join(s.ToArgs(), " ")
}

// ToArgs renders the strategy to nfqws2 argument tokens (filters first, then the
// action chain in order). It does not emit --lua-init or --qnum; those are added
// by the worker at launch time.
func (s Strategy) ToArgs() []string {
	var args []string

	if s.Filter.TCP != "" {
		args = append(args, "--filter-tcp="+s.Filter.TCP)
	}
	if s.Filter.UDP != "" {
		args = append(args, "--filter-udp="+s.Filter.UDP)
	}
	if len(s.Filter.L7) > 0 {
		args = append(args, "--filter-l7="+strings.Join(s.Filter.L7, ","))
	}
	if len(s.Filter.Payload) > 0 {
		args = append(args, "--payload="+strings.Join(s.Filter.Payload, ","))
	}

	for _, a := range s.Actions {
		args = append(args, a.arg())
	}

	return args
}

// arg renders a single action instance as "--lua-desync=func[:param...]".
func (a Action) arg() string {
	var b strings.Builder
	b.WriteString("--lua-desync=")
	b.WriteString(a.Func)
	for _, p := range a.Params {
		b.WriteByte(':')
		b.WriteString(p.Key)
		if p.Value != "" {
			b.WriteByte('=')
			b.WriteString(p.Value)
		}
	}
	return b.String()
}
