package evolution

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"

	"prikop/internal/model"
	"prikop/internal/nfqws2"
)

const (
	// SmartMutate group-1 (signature match) branch thresholds
	ProbResetSplit = 0.4
	ProbResetFake  = 0.7

	// group-2 (timeout / loss / inconclusive) branch thresholds
	ProbTimeoutRepeat = 0.4
	ProbTimeoutMode   = 0.7

	// default/random op weights (cumulative, out of 100)
	ProbMutateSplit   = 20
	ProbMutateFake    = 35
	ProbMutateMode    = 50
	ProbMutateFooling = 65
	ProbMutateTamper  = 80
	ProbMutateTTL     = 90

	// split heuristics
	ProbSplitMulti  = 0.4
	ProbSplitDouble = 0.3
	ProbSplitSeqOvl = 0.6

	// fake heuristics
	ProbFakeTLSMod = 0.6
	ProbFakeSNI    = 0.2

	// fooling flip probabilities
	ProbFoolingFlip  = 0.3
	ProbFoolingRisky = 0.05

	// global/misc
	ProbGlobalRepeats = 0.3
	ProbGlobalWSS     = 0.7

	// TTL heuristics
	ProbTTLAuto  = 0.6
	ProbTTLFixed = 0.9

	// wssize toggle-off probability when one already exists
	ProbWSSDrop = 0.4

	MaxRepeatsTCP     = 6
	MaxRepeatsUDP     = 10
	MinRepeats        = 1
	MaxRepeatsOverall = 10

	// Canonical badseq/badack fooling values (v1 badseq -> v2 tcp_seq/tcp_ack).
	BadSeqValue = "-10000" // tcp_seq, for SYN-time actions
	BadAckValue = "-66000" // tcp_ack, for data actions (+ tcp_ts_up on Linux)
)

var (
	magicSeqOvls = []int{336, 620, 109, 652, 1, 133, 500, 32, 2}
	// CommonSNIs / CommonHosts are consumed by package galaxy too — keep exported.
	CommonSNIs = []string{
		"www.gosuslugi.ru", "sberbank.ru", "sun6-21.userapi.com",
		"ya.ru", "eh.vk.com", "support.mcs.mail.ru", "api.ok.ru",
		"00.img.avito.st", "goya.rutube.ru", "mapgl.2gis.com", "www.google.com", "ggpht.com",
		"xn--80ajghhoc2aj1c8b.xn--p1ai", "i0.photo.2gis.com",
	}
	CommonHosts = []string{
		"www.gosuslugi.ru", "sberbank.ru", "sun6-21.userapi.com",
		"ya.ru", "eh.vk.com", "support.mcs.mail.ru",
		"00.img.avito.st", "goya.rutube.ru", "mapgl.2gis.com", "api.ok.ru",
	}
	tamperSpells = []string{"HOst", "hoSt", "hOst", "host"}

	// Blob pools: only default named blobs or 0xHEX literals are allowed (no
	// /app/fake/*.bin file paths yet, per the migration contract).
	tlsBlobs = []string{
		nfqws2.BlobDefaultTLS,
		"0x1603010200010000", "0x160301", "0x16030100",
	}
	quicBlobs = []string{
		nfqws2.BlobDefaultQUIC,
		"0xc00000000108", "0xcd0000000108",
	}
	tlsMods = []string{"rnd", "rndsni", "rnd,dupsid", "dupsid", "padencap", ""}

	// wsize/scale pairs for the wssize action (v1 "1:6" -> wsize=1:scale=6).
	wsizePairs = [][2]string{
		{"1", "6"}, {"1", "8"}, {"1", "10"}, {"512", ""}, {"1400", ""}, {"2048", "2"},
	}

	methodEols = []string{"cr", "lf", "crlf", "lfcr"}

	httpTamperFuncs = []string{"http_hostcase", "http_domcase", "http_methodeol", "http_unixeol"}

	// IPv6-only extension-header foolings — dropped (prikop targets the IPv4 path).
	ipv6OnlyParams = []string{
		"ip6_hopbyhop", "ip6_hopbyhop2", "ip6_destopt", "ip6_destopt2",
		"ip6_routing", "ip6_ah",
	}
	// TCP-only foolings, meaningless on a UDP/QUIC profile.
	tcpOnlyParams = []string{
		"tcp_md5", "tcp_seq", "tcp_ack", "tcp_ts", "tcp_ts_up",
		"tcp_flags_set", "tcp_flags_unset",
	}
)

type Mutator struct {
	AvailableBins []string
	Proto         string
}

func NewMutator(bins []string, proto string) *Mutator {
	return &Mutator{AvailableBins: bins, Proto: proto}
}

func (m *Mutator) Mutate(s *nfqws2.Strategy) {
	m.SmartMutate(s, model.ReasonNone)
}

func (m *Mutator) SmartMutate(s *nfqws2.Strategy, feedback model.FailureReason) {
	r := rand.Float64()
	m.sanitize(s)

	switch feedback {
	// === GROUP 1: HARD BLOCK (signature match) ===
	// DPI recognised the protocol and reset/spoofed the connection.
	// Response: aggressively reshape the fake/split to hide the signature.
	case model.ReasonReset,
		model.ReasonTLSNotTLS,
		model.ReasonTLSOversized,
		model.ReasonTLSRecordOverflow,
		model.ReasonTLSUnrecognizedName:

		if r < ProbResetSplit {
			m.mutateSplit(s) // shift the break point (around SNI/host)
		} else if r < ProbResetFake {
			m.mutateFake(s) // swap the fake payload signature
		} else {
			m.mutateTamper(s) // toggle a tamper-style http func
		}

	// === GROUP 2: PACKET LOSS / TIMEOUTS / INCONCLUSIVE ===
	// Packets don't arrive or the verdict is ambiguous.
	// Response: change delivery params or simplify.
	case model.ReasonTimeout,
		model.ReasonSkip,
		model.ReasonTLSHandshake,
		model.ReasonTLSInternal:

		if feedback == model.ReasonSkip && r < 0.3 {
			m.mutateSimplify(s)
		} else if r < ProbTimeoutRepeat {
			m.mutateRepeats(s)
		} else if r < ProbTimeoutMode {
			m.mutateMode(s)
		} else {
			m.mutateTTL(s)
		}

	// === GROUP 3: MITM / INTERVENTION ===
	// DPI wedges into the handshake, downgrades, or spoofs the cert.
	// Response: break sync (synack_split), disorder, or force server split (wssize).
	case model.ReasonTLSALPN,
		model.ReasonTLSVersion,
		model.ReasonTLSCipherSuite,
		model.ReasonTLSDowngrade,
		model.ReasonTLSBadSignature,
		model.ReasonTLSIllegalParam,
		model.ReasonTLSSessionID:

		if !s.HasFunc("synack_split") && r < 0.4 {
			// prepend the synack_split phase-0 action
			s.Actions = append([]nfqws2.Action{{Func: "synack_split"}}, s.Actions...)
		} else if r < 0.7 {
			m.mutateWSS(s) // force server-side fragmentation
		} else {
			// disorder is effective against MITM: DPI can't reassemble.
			if !s.HasFunc("disorder") {
				m.toDisorder(s)
				m.mutateSplit(s)
			} else {
				// already disorder: reroll the overlap on the disorder action
				for i := range s.Actions {
					if strings.Contains(s.Actions[i].Func, "disorder") {
						s.Actions[i].SetParam("seqovl", strconv.Itoa(magicSeqOvls[rand.IntN(len(magicSeqOvls))]))
					}
				}
			}
		}

	// === GROUP 4: DATA CORRUPTION ===
	// We broke the packet so badly the peer can't read it. Roll back aggression.
	case model.ReasonTLSBadMAC,
		model.ReasonTLSDecrypt,
		model.ReasonTLSDecode,
		model.ReasonTLSAlertUnexpected:

		m.mutateSimplify(s)

	// === GROUP 5: SHAPING ===
	case model.ReasonThrottle:
		m.mutateWSS(s)
		if r < 0.5 {
			m.mutateSplit(s)
		}

	// === DEFAULT / RANDOM ===
	default:
		choice := rand.IntN(100)
		switch {
		case choice < ProbMutateSplit:
			m.mutateSplit(s)
		case choice < ProbMutateFake:
			m.mutateFake(s)
		case choice < ProbMutateMode:
			m.mutateMode(s)
			if s.HasFunc("fake") {
				m.mutateFake(s)
			}
		case choice < ProbMutateFooling:
			m.mutateFooling(s)
		case choice < ProbMutateTamper:
			m.mutateTamper(s)
		case choice < ProbMutateTTL:
			m.mutateTTL(s)
		default:
			m.mutateGlobal(s)
		}
	}

	m.sanitize(s)
}

// ---- operators ---------------------------------------------------------------

// mutateSimplify reduces aggressiveness when the strategy corrupts the stream.
func (m *Mutator) mutateSimplify(s *nfqws2.Strategy) {
	for i := range s.Actions {
		a := &s.Actions[i]
		// 1. drop NAT-fragile / corrupting foolings
		a.DelParam("badsum")
		a.DelParam("tcp_seq")
		a.DelParam("tcp_ack")
		a.DelParam("tcp_ts_up")
		// 2. drop overlap (SeqOvl damages payload)
		a.DelParam("seqovl")
		a.DelParam("seqovl_pattern")
		// 3. drop fake modifiers
		a.DelParam("tls_mod")
		// 4. reset repeats to the minimum
		a.DelParam("repeats")
		// 5. disorder -> split (disorder often breaks TLS 1.3 state)
		a.Func = simplifyFunc(a.Func)
	}
}

func (m *Mutator) mutateSplit(s *nfqws2.Strategy) {
	idx := m.splitIdx(s)
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "multisplit"})
		idx = len(s.Actions) - 1
	}
	a := &s.Actions[idx]

	if a.Func == "hostfakesplit" {
		a.SetParam("host", CommonHosts[rand.IntN(len(CommonHosts))])
		a.DelParam("seqovl")
		return
	}

	a.SetParam("pos", m.genSplitPos(a.Func))

	if rand.Float64() < ProbSplitSeqOvl {
		a.SetParam("seqovl", strconv.Itoa(magicSeqOvls[rand.IntN(len(magicSeqOvls))]))
	} else {
		a.SetParam("seqovl", strconv.Itoa(1+rand.IntN(5)))
	}
}

// genSplitPos mirrors the v1 marker heuristic, biased toward SNI/host breaks.
func (m *Mutator) genSplitPos(fn string) string {
	markers := []string{
		"midsld", "sniext", "endsld", // high priority (break inside domain/SNI)
		"method", "host", // medium priority
		"2", "3", // low priority (magic numbers)
	}

	gen := func() string {
		marker := markers[rand.IntN(len(markers))]
		if len(marker) < 3 { // bare numeric marker
			return marker
		}
		offset := rand.IntN(5) - 2 // -2..+2
		if offset == 0 {
			return marker
		}
		if offset > 0 {
			return fmt.Sprintf("%s+%d", marker, offset)
		}
		return fmt.Sprintf("%s%d", marker, offset) // negative sign already present
	}

	isMulti := fn == "multisplit" || fn == "multidisorder"
	switch {
	case isMulti && rand.Float64() < ProbSplitMulti:
		return "1," + gen()
	case rand.Float64() < ProbSplitDouble:
		return gen() + "," + gen()
	default:
		return gen()
	}
}

func (m *Mutator) mutateFake(s *nfqws2.Strategy) {
	idx := findFunc(s, "fake")
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "fake"})
		idx = len(s.Actions) - 1
	}
	a := &s.Actions[idx]
	a.SetParam("blob", m.pickBlob())

	if m.Proto == "tcp" && rand.Float64() < ProbFakeTLSMod {
		if rand.Float64() < ProbFakeSNI {
			a.SetParam("tls_mod", "sni="+CommonSNIs[rand.IntN(len(CommonSNIs))])
		} else {
			mod := tlsMods[rand.IntN(len(tlsMods))]
			if mod == "" {
				a.DelParam("tls_mod")
			} else {
				a.SetParam("tls_mod", mod)
			}
		}
	} else {
		a.DelParam("tls_mod")
	}
}

// mutateMode switches the primary desync function (fake <-> split family).
func (m *Mutator) mutateMode(s *nfqws2.Strategy) {
	var bases []string
	if m.Proto == "tcp" {
		bases = []string{"fake", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"}
	} else {
		bases = []string{"fake", "multisplit", "udplen"}
	}
	newFunc := bases[rand.IntN(len(bases))]

	idx := m.primaryIdx(s)
	if idx < 0 {
		s.Actions = append(s.Actions, nfqws2.Action{Func: newFunc})
		return
	}
	// Switch func and clear now-irrelevant params; sanitize re-adds blob/pos.
	s.Actions[idx].Func = newFunc
	s.Actions[idx].Params = nil
}

func (m *Mutator) mutateFooling(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]

	flipFlag := func(key string, prob float64) {
		if rand.Float64() >= prob {
			return
		}
		if _, ok := a.Param(key); ok {
			a.DelParam(key)
		} else {
			a.SetParam(key, "")
		}
	}

	if m.Proto == "tcp" {
		flipFlag("tcp_md5", ProbFoolingFlip)
		// badsum/badseq are NAT-fragile: heavily biased OFF via the score penalty.
		flipFlag("badsum", ProbFoolingRisky)
		if rand.Float64() < ProbFoolingRisky {
			if hasBadSeq(a) {
				clearBadSeq(a)
			} else {
				setBadSeq(a)
			}
		}
		// datanoack -> tcp_flags_unset=ack
		if rand.Float64() < ProbFoolingFlip {
			if _, ok := a.Param("tcp_flags_unset"); ok {
				a.DelParam("tcp_flags_unset")
			} else {
				a.SetParam("tcp_flags_unset", "ack")
			}
		}
	} else {
		flipFlag("badsum", ProbFoolingRisky)
	}
}

// mutateTamper toggles a tamper-style http_* function (TCP/HTTP only).
func (m *Mutator) mutateTamper(s *nfqws2.Strategy) {
	if m.Proto != "tcp" {
		return
	}
	fn := httpTamperFuncs[rand.IntN(len(httpTamperFuncs))]
	if i := findFunc(s, fn); i >= 0 {
		s.Actions = append(s.Actions[:i], s.Actions[i+1:]...)
		return
	}
	a := nfqws2.Action{Func: fn}
	switch fn {
	case "http_hostcase":
		a.SetParam("spell", tamperSpells[rand.IntN(len(tamperSpells))])
	case "http_methodeol":
		if rand.Float64() < 0.5 {
			a.SetParam("method", methodEols[rand.IntN(len(methodEols))])
		}
	}
	s.Actions = append(s.Actions, a)
}

func (m *Mutator) mutateTTL(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]
	a.DelParam("ip_ttl")
	a.DelParam("ip6_ttl")
	a.DelParam("ip_autottl")
	a.DelParam("ip6_autottl")

	r := rand.Float64()
	if r < ProbTTLAuto {
		delta := -(1 + rand.IntN(3)) // -1..-3
		val := fmt.Sprintf("%d,3-20", delta)
		a.SetParam("ip_autottl", val)
		a.SetParam("ip6_autottl", val)
	} else if r < ProbTTLFixed {
		ttl := 1 + rand.IntN(10)
		a.SetParam("ip_ttl", strconv.Itoa(ttl))
	}
	// else: no TTL fooling
}

func (m *Mutator) mutateRepeats(s *nfqws2.Strategy) {
	idx := m.primaryIdx(s)
	if idx < 0 {
		return
	}
	a := &s.Actions[idx]

	cur := 1
	if v, ok := a.Param("repeats"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cur = n
		}
	}
	cur += rand.IntN(3) - 1

	maxR := MaxRepeatsTCP
	if m.Proto == "udp" {
		maxR = MaxRepeatsUDP
	}
	if cur > maxR {
		cur = maxR
	}
	if cur < MinRepeats {
		cur = MinRepeats
	}
	if cur == 1 {
		a.DelParam("repeats")
	} else {
		a.SetParam("repeats", strconv.Itoa(cur))
	}
}

// mutateWSS adds/removes/retunes a wssize action (forces server-side split).
func (m *Mutator) mutateWSS(s *nfqws2.Strategy) {
	if i := findFunc(s, "wssize"); i >= 0 {
		if rand.Float64() < ProbWSSDrop {
			s.Actions = append(s.Actions[:i], s.Actions[i+1:]...)
			return
		}
		setWsize(&s.Actions[i])
		return
	}
	a := nfqws2.Action{Func: "wssize"}
	setWsize(&a)
	s.Actions = append(s.Actions, a)
}

func (m *Mutator) mutateGlobal(s *nfqws2.Strategy) {
	r := rand.Float64()
	switch {
	case r < ProbGlobalRepeats:
		m.mutateRepeats(s)
	case r < ProbGlobalWSS:
		m.mutateWSS(s)
	default:
		if m.Proto == "udp" {
			inc := rand.IntN(32) - 16
			if inc == 0 {
				inc = 2
			}
			if i := findFunc(s, "udplen"); i >= 0 {
				s.Actions[i].SetParam("increment", strconv.Itoa(inc))
			} else {
				s.Actions = append(s.Actions, nfqws2.Action{
					Func:   "udplen",
					Params: []nfqws2.Param{nfqws2.P("increment", strconv.Itoa(inc))},
				})
			}
		} else {
			m.mutateRepeats(s)
		}
	}
}

// ---- sanitize ----------------------------------------------------------------

// sanitize canonicalises a strategy into a valid, phase-ordered genome:
//   - drop actions whose func is outside KnownFuncs (covers IPv6-only pseudo-funcs)
//   - strip IPv6-only extension-header foolings (and TCP foolings on UDP)
//   - reorder actions into canonical phases (synack | fake/rst | split family)
//   - ensure fake/syndata actions carry a blob, split actions carry a pos
//   - clamp repeats into [MinRepeats, MaxRepeatsOverall]
//   - normalise blobs to the profile proto (TLS on TCP, QUIC on UDP)
//   - dedupe identical actions and guarantee a non-empty strategy + filter
//
// The result always passes nfqws2.Strategy.Valid().
func (m *Mutator) sanitize(s *nfqws2.Strategy) {
	// 1. drop unknown/IPv6-only funcs; strip incompatible params.
	kept := s.Actions[:0:0]
	for _, a := range s.Actions {
		if _, ok := nfqws2.KnownFuncs[a.Func]; !ok {
			continue
		}
		for _, k := range ipv6OnlyParams {
			a.DelParam(k)
		}
		if m.Proto == "udp" {
			for _, k := range tcpOnlyParams {
				a.DelParam(k)
			}
		}
		kept = append(kept, a)
	}
	s.Actions = kept

	// 2. stable phase reorder.
	sort.SliceStable(s.Actions, func(i, j int) bool {
		return funcPhase(s.Actions[i].Func) < funcPhase(s.Actions[j].Func)
	})

	// 3. per-action fixups.
	for i := range s.Actions {
		a := &s.Actions[i]

		if v, ok := a.Param("blob"); ok && v != "" {
			a.SetParam("blob", m.protoBlob(v))
		}
		if needsBlob(a.Func) {
			if v, ok := a.Param("blob"); !ok || v == "" {
				a.SetParam("blob", m.defaultBlob())
			}
		}

		switch {
		case a.Func == "tcpseg":
			if _, ok := a.Param("pos"); !ok {
				a.SetParam("pos", "1,midsld")
			}
		case needsPos(a.Func):
			if _, ok := a.Param("pos"); !ok {
				a.SetParam("pos", "2")
			}
		}

		if v, ok := a.Param("repeats"); ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < MinRepeats {
				n = MinRepeats
			}
			if n > MaxRepeatsOverall {
				n = MaxRepeatsOverall
			}
			if n == 1 {
				a.DelParam("repeats")
			} else {
				a.SetParam("repeats", strconv.Itoa(n))
			}
		}
	}

	// 4. dedupe identical actions (keep first occurrence).
	s.Actions = dedupeActions(s.Actions)

	// 5. never leave an empty genome.
	if len(s.Actions) == 0 {
		s.Actions = []nfqws2.Action{m.defaultAction()}
	}

	// 6. guarantee a filter matching the proto.
	m.ensureFilter(s)
}

// ---- helpers -----------------------------------------------------------------

// funcPhase returns the canonical phase bucket of a known desync function.
// Lower phases render first: synack/window setup, then fakes, then tamper, then
// the split/segment family.
func funcPhase(fn string) int {
	switch fn {
	case "synack_split", "synack", "wsize", "wssize", "syndata":
		return 0
	case "fake", "rst":
		return 1
	case "http_hostcase", "http_domcase", "http_methodeol", "http_unixeol":
		return 2
	default:
		// multisplit, multidisorder, fakedsplit, fakeddisorder, hostfakesplit,
		// tcpseg, udplen, drop, send, pktmod, dht_dn
		return 3
	}
}

func isSplitFunc(fn string) bool {
	switch fn {
	case "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "tcpseg":
		return true
	}
	return false
}

func needsBlob(fn string) bool {
	return fn == "fake" || fn == "syndata"
}

func needsPos(fn string) bool {
	switch fn {
	case "multisplit", "multidisorder", "fakedsplit", "fakeddisorder":
		return true
	}
	return false
}

func simplifyFunc(fn string) string {
	switch fn {
	case "multidisorder":
		return "multisplit"
	case "fakeddisorder":
		return "fakedsplit"
	default:
		return fn
	}
}

// toDisorder converts split-family actions to their disorder variant, or adds a
// multidisorder if none is present.
func (m *Mutator) toDisorder(s *nfqws2.Strategy) {
	converted := false
	for i := range s.Actions {
		switch s.Actions[i].Func {
		case "multisplit":
			s.Actions[i].Func = "multidisorder"
			converted = true
		case "fakedsplit":
			s.Actions[i].Func = "fakeddisorder"
			converted = true
		}
	}
	if !converted {
		s.Actions = append(s.Actions, nfqws2.Action{Func: "multidisorder"})
	}
}

// primaryIdx returns the index of the action fooling/TTL/repeats attach to:
// prefer a split-family action, then a fake, then the first action.
func (m *Mutator) primaryIdx(s *nfqws2.Strategy) int {
	if i := m.splitIdx(s); i >= 0 {
		return i
	}
	if i := findFunc(s, "fake"); i >= 0 {
		return i
	}
	if len(s.Actions) > 0 {
		return 0
	}
	return -1
}

// splitIdx returns the index of the first split-family action, or -1.
func (m *Mutator) splitIdx(s *nfqws2.Strategy) int {
	for i := range s.Actions {
		if isSplitFunc(s.Actions[i].Func) {
			return i
		}
	}
	return -1
}

func findFunc(s *nfqws2.Strategy, fn string) int {
	for i := range s.Actions {
		if s.Actions[i].Func == fn {
			return i
		}
	}
	return -1
}

func (m *Mutator) pickBlob() string {
	if m.Proto == "udp" {
		return quicBlobs[rand.IntN(len(quicBlobs))]
	}
	return tlsBlobs[rand.IntN(len(tlsBlobs))]
}

func (m *Mutator) defaultBlob() string {
	if m.Proto == "udp" {
		return nfqws2.BlobDefaultQUIC
	}
	return nfqws2.BlobDefaultTLS
}

// protoBlob keeps the default blob consistent with the profile transport.
// Custom 0xHEX blobs are left untouched.
func (m *Mutator) protoBlob(blob string) string {
	if m.Proto == "udp" && blob == nfqws2.BlobDefaultTLS {
		return nfqws2.BlobDefaultQUIC
	}
	if m.Proto == "tcp" && blob == nfqws2.BlobDefaultQUIC {
		return nfqws2.BlobDefaultTLS
	}
	return blob
}

func (m *Mutator) defaultAction() nfqws2.Action {
	return nfqws2.Action{
		Func:   "fake",
		Params: []nfqws2.Param{nfqws2.P("blob", m.defaultBlob())},
	}
}

func (m *Mutator) ensureFilter(s *nfqws2.Strategy) {
	if s.Filter.TCP != "" || s.Filter.UDP != "" {
		return
	}
	if m.Proto == "udp" {
		s.Filter = nfqws2.Filter{UDP: "443", L7: []string{"quic"}, Payload: []string{"quic_initial"}}
	} else {
		s.Filter = nfqws2.Filter{TCP: "80,443", L7: []string{"tls", "http"}, Payload: []string{"tls_client_hello"}}
	}
}

func setWsize(a *nfqws2.Action) {
	p := wsizePairs[rand.IntN(len(wsizePairs))]
	a.SetParam("wsize", p[0])
	if p[1] != "" {
		a.SetParam("scale", p[1])
	} else {
		a.DelParam("scale")
	}
}

func hasBadSeq(a *nfqws2.Action) bool {
	if _, ok := a.Param("tcp_seq"); ok {
		return true
	}
	_, ok := a.Param("tcp_ack")
	return ok
}

// setBadSeq maps v1 badseq onto v2: tcp_seq for SYN-time actions, tcp_ack (+
// tcp_ts_up, the Linux badack workaround) for data actions.
func setBadSeq(a *nfqws2.Action) {
	if a.Func == "syndata" || a.Func == "synack_split" || a.Func == "synack" {
		a.SetParam("tcp_seq", BadSeqValue)
		return
	}
	a.SetParam("tcp_ack", BadAckValue)
	a.SetParam("tcp_ts_up", "")
}

func clearBadSeq(a *nfqws2.Action) {
	a.DelParam("tcp_seq")
	a.DelParam("tcp_ack")
	a.DelParam("tcp_ts_up")
}

func dedupeActions(as []nfqws2.Action) []nfqws2.Action {
	seen := make(map[string]struct{}, len(as))
	out := as[:0:0]
	for _, a := range as {
		key := actionKey(a)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

func actionKey(a nfqws2.Action) string {
	var b strings.Builder
	b.WriteString(a.Func)
	for _, p := range a.Params {
		b.WriteByte('|')
		b.WriteString(p.Key)
		b.WriteByte('=')
		b.WriteString(p.Value)
	}
	return b.String()
}
