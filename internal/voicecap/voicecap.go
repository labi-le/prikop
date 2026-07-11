// Package voicecap runs a capture-based Discord-voice DPI-bypass check: it
// sniffs UDP for a few seconds and reports whether the discord.media voice flow
// is BIDIRECTIONAL (the server answers => voice UDP crossed the DPI) or
// outbound-only (blocked). Direction is inferred from which side uses a Discord
// voice port, so no local/remote IP knowledge is needed and it behaves the same
// on a LAN host or a router WAN. Needs root + tcpdump.
//
// Discord mandates the DAVE (E2EE) protocol for all non-stage voice, so no Go
// bot can complete the voice handshake and be probed actively — sniffing a real
// call is the only workable test.
package voicecap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Filter is the BPF for Discord voice: RTP on udp 19294-19344 / 50000-50100,
// plus IP-discovery, which carries the STUN magic cookie 0x2112a442.
const Filter = "udp and (portrange 19294-19344 or portrange 50000-50100 or udp[12:4]=0x2112a442)"

// Flow is one discord.media voice endpoint and its packet tallies. Server is the
// side using a Discord voice port ("ip.port").
type Flow struct {
	Server            string
	OutPkts, InPkts   int
	OutBytes, InBytes int
}

// Result holds the classified capture. Flows are sorted by total packets desc;
// Bidirectional reflects the top flow (server answering => bypass works).
type Result struct {
	Flows         []Flow
	Bidirectional bool
}

func inVoiceRange(p int) bool { return (p >= 19294 && p <= 19344) || (p >= 50000 && p <= 50100) }

func splitIPPort(s string) (string, int) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return s[:i], p
}

// Classify parses `tcpdump -tt -n` UDP lines and groups them by Discord voice
// server (the endpoint using a voice port), counting direction. A packet whose
// destination port is a voice port is outbound (client -> server); a voice
// source port is inbound (server -> client). Non-IPv4 / malformed lines are
// ignored.
func Classify(lines []string) Result {
	type acc struct{ outP, inP, outB, inB int }
	flows := map[string]*acc{}
	get := func(k string) *acc {
		a := flows[k]
		if a == nil {
			a = &acc{}
			flows[k] = a
		}
		return a
	}
	for _, ln := range lines {
		f := strings.Fields(ln)
		// <ts> IP <src> > <dst>: UDP, length <n>
		if len(f) < 8 || f[1] != "IP" || f[3] != ">" {
			continue
		}
		sip, sp := splitIPPort(f[2])
		dip, dp := splitIPPort(strings.TrimSuffix(f[4], ":"))
		n, _ := strconv.Atoi(f[len(f)-1])
		switch {
		case inVoiceRange(sp):
			a := get(sip + "." + strconv.Itoa(sp))
			a.inP++
			a.inB += n
		case inVoiceRange(dp):
			a := get(dip + "." + strconv.Itoa(dp))
			a.outP++
			a.outB += n
		}
	}
	res := Result{}
	for k, a := range flows {
		res.Flows = append(res.Flows, Flow{Server: k, OutPkts: a.outP, InPkts: a.inP, OutBytes: a.outB, InBytes: a.inB})
	}
	sort.Slice(res.Flows, func(i, j int) bool {
		return res.Flows[i].OutPkts+res.Flows[i].InPkts > res.Flows[j].OutPkts+res.Flows[j].InPkts
	})
	if len(res.Flows) > 0 {
		res.Bidirectional = res.Flows[0].InPkts > 0
	}
	return res
}

// DefaultIface returns the default-route interface, or "any" if it can't tell.
func DefaultIface() string {
	out, err := exec.Command("ip", "-o", "route", "get", "1.1.1.1").Output()
	if err == nil {
		f := strings.Fields(string(out))
		for i, w := range f {
			if w == "dev" && i+1 < len(f) {
				return f[i+1]
			}
		}
	}
	return "any"
}

// Capture runs tcpdump on iface for dur with the Discord voice Filter and
// returns the classified result. Requires root + tcpdump in PATH.
func Capture(ctx context.Context, iface string, dur time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tcpdump", "-ni", iface, "-tt", "-l", "-c", "200000", Filter)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		err = nil // expected: we stop tcpdump once the window elapses
	}
	if err != nil && out.Len() == 0 {
		return Result{}, fmt.Errorf("tcpdump: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return Classify(strings.Split(out.String(), "\n")), nil
}
