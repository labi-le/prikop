package nfqws2

import "strings"

// Clone returns a deep copy safe to mutate independently (Actions and their
// Params slices are copied, not shared).
func (s Strategy) Clone() Strategy {
	c := s
	if s.Filter.L7 != nil {
		c.Filter.L7 = append([]string(nil), s.Filter.L7...)
	}
	if s.Filter.Payload != nil {
		c.Filter.Payload = append([]string(nil), s.Filter.Payload...)
	}
	c.Actions = make([]Action, len(s.Actions))
	for i, a := range s.Actions {
		a.Params = append([]Param(nil), a.Params...)
		c.Actions[i] = a
	}
	return c
}

// HasFunc reports whether any action's function name contains sub
// (e.g. "fake", "split", "disorder").
func (s Strategy) HasFunc(sub string) bool {
	for _, a := range s.Actions {
		if strings.Contains(a.Func, sub) {
			return true
		}
	}
	return false
}

// Signature is the cluster key for evolution diversity: the ordered action
// function names joined by commas (e.g. "fake,multisplit").
func (s Strategy) Signature() string {
	funcs := make([]string, len(s.Actions))
	for i, a := range s.Actions {
		funcs[i] = a.Func
	}
	return strings.Join(funcs, ",")
}

// SplitPos returns the "pos" param of the first split/disorder action, or "".
func (s Strategy) SplitPos() string {
	for _, a := range s.Actions {
		if strings.Contains(a.Func, "split") || strings.Contains(a.Func, "disorder") {
			if v, ok := a.Param("pos"); ok {
				return v
			}
		}
	}
	return ""
}

// HasParam reports whether any action carries a param with the given key
// (e.g. "badsum", "tcp_md5", "tcp_seq").
func (s Strategy) HasParam(key string) bool {
	for _, a := range s.Actions {
		if _, ok := a.Param(key); ok {
			return true
		}
	}
	return false
}

// HasBadSeq reports whether the strategy uses badseq/badack-style fooling
// (the NAT-fragile methods penalized by the score).
func (s Strategy) HasBadSeq() bool {
	return s.HasParam("tcp_seq") || s.HasParam("tcp_ack")
}

// Complexity is a proxy for command size used by the score's simplicity
// penalty: number of action instances plus total params.
func (s Strategy) Complexity() int {
	n := len(s.Actions)
	for _, a := range s.Actions {
		n += len(a.Params)
	}
	return n
}

// IsUDP reports whether the profile targets UDP/QUIC.
func (s Strategy) IsUDP() bool {
	if s.Filter.UDP != "" {
		return true
	}
	for _, l7 := range s.Filter.L7 {
		if l7 == "quic" {
			return true
		}
	}
	for _, p := range s.Filter.Payload {
		if strings.HasPrefix(p, "quic") {
			return true
		}
	}
	return false
}

// Param returns the value of the named param and whether it is present.
// A boolean flag returns ("", true).
func (a Action) Param(key string) (string, bool) {
	for _, p := range a.Params {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

// SetParam sets (or appends) a param, preserving order for existing keys.
func (a *Action) SetParam(key, value string) {
	for i := range a.Params {
		if a.Params[i].Key == key {
			a.Params[i].Value = value
			return
		}
	}
	a.Params = append(a.Params, Param{Key: key, Value: value})
}

// DelParam removes a param by key if present.
func (a *Action) DelParam(key string) {
	for i := range a.Params {
		if a.Params[i].Key == key {
			a.Params = append(a.Params[:i], a.Params[i+1:]...)
			return
		}
	}
}
