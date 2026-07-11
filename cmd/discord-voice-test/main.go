// Command discord-voice-test probes UDP/STUN reachability the way Discord voice
// negotiates: it sends a STUN Binding Request (RFC 5389) to an endpoint and
// waits for a Binding Success Response.
//
// Methodology (two parts — a bare STUN probe alone is NOT enough for Discord):
//
//  1. UDP/STUN path check (this tool). Probe a PUBLIC STUN server; a response
//     proves plain UDP + STUN round-trips survive the DPI/zapret path:
//
//     go run ./cmd/discord-voice-test stun.l.google.com 19302
//
//  2. Discord-specific proof (packet capture on the router). Discord's own
//     <region>.discord.media voice servers are SESSION-GATED: they answer only
//     the client's authenticated session socket, so a bare STUN Binding Request
//     from this tool times out even when voice works. Confirm real voice by
//     capturing the live call on the router while you are in a voice channel:
//
//     tcpdump -ni wan 'udp[12:4] = 0x2112a442'            # STUN negotiation
//     tcpdump -ni wan 'udp portrange 50000-50100'         # RTP media
//
//     Bidirectional packets to/from <server>:5000x  ==  voice UDP works.
//     This tool can then probe that captured <server> <port> as a spot check.
//
// Usage:
//
//	go run ./cmd/discord-voice-test [flags] [<host> <port> ...]
//
// With no targets it runs the UDP/STUN path check against public STUN servers.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	stunBindingRequest = 0x0001
	stunMagicCookie    = 0x2112A442
	stunBindingSuccess = 0x0101
	attrXorMappedAddr  = 0x0020
)

// defaultTargets are public STUN servers used for the UDP/STUN path check when
// the caller passes no explicit endpoint.
var defaultTargets = [][2]string{
	{"stun.l.google.com", "19302"},
	{"stun.cloudflare.com", "3478"},
}

// probe sends one STUN Binding Request to host:port and reports whether a
// Binding Success Response returned, its round-trip time, and the XOR-MAPPED
// public address the server observed (the ip:port a peer would advertise).
func probe(host, port string, timeout time.Duration) (ok bool, rtt time.Duration, mapped string, err error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false, 0, "", err
	}
	defer conn.Close()

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // message length
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	if _, err = rand.Read(req[8:20]); err != nil { // 96-bit transaction id
		return false, 0, "", err
	}

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, 0, "", err
	}
	start := time.Now()
	if _, err = conn.Write(req); err != nil {
		return false, 0, "", err
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return false, 0, "", err
	}
	rtt = time.Since(start)
	if n < 20 || binary.BigEndian.Uint16(resp[0:2]) != stunBindingSuccess {
		return false, rtt, "", fmt.Errorf("not a STUN Binding Success (0x%04x)", binary.BigEndian.Uint16(resp[0:2]))
	}
	return true, rtt, xorMappedAddr(resp[:n]), nil
}

// xorMappedAddr extracts the XOR-MAPPED-ADDRESS attribute (IPv4) if present.
func xorMappedAddr(b []byte) string {
	for i := 20; i+4 <= len(b); {
		atype := binary.BigEndian.Uint16(b[i : i+2])
		alen := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		v := b[i+4:]
		if atype == attrXorMappedAddr && alen >= 8 && len(v) >= 8 {
			port := binary.BigEndian.Uint16(v[2:4]) ^ (stunMagicCookie >> 16)
			ip := net.IPv4(v[4]^0x21, v[5]^0x12, v[6]^0xa4, v[7]^0x42)
			return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		}
		i += 4 + alen + (4-alen%4)%4 // attributes are 32-bit aligned
	}
	return ""
}

func main() {
	timeout := flag.Duration("timeout", 3*time.Second, "per-attempt UDP timeout")
	retries := flag.Int("retries", 3, "STUN attempts before declaring blocked")
	flag.Parse()

	var targets [][2]string
	args := flag.Args()
	switch {
	case len(args) == 0:
		targets = defaultTargets
	case len(args)%2 == 0:
		for i := 0; i+1 < len(args); i += 2 {
			targets = append(targets, [2]string{args[i], args[i+1]})
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: discord-voice-test [-timeout 3s] [-retries 3] [<host> <port> ...]")
		os.Exit(2)
	}

	failed := false
	for _, t := range targets {
		host, port := t[0], t[1]
		if _, err := strconv.Atoi(port); err != nil {
			fmt.Printf("FAIL  %s -> bad port %q\n", host, port)
			failed = true
			continue
		}
		target := net.JoinHostPort(host, port)
		var lastErr error
		var passed bool
		for a := 0; a < *retries; a++ {
			ok, rtt, mapped, err := probe(host, port, *timeout)
			if ok {
				fmt.Printf("PASS  %-26s STUN %v  public=%s\n", target, rtt.Round(time.Millisecond), mapped)
				passed = true
				break
			}
			lastErr = err
			time.Sleep(200 * time.Millisecond)
		}
		if !passed {
			fmt.Printf("FAIL  %-26s no STUN response x%d: %v\n", target, *retries, lastErr)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
