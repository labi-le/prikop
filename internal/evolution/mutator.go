package evolution

import (
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
		nfqws2.BlobDefaultTLS, nfqws2.BlobGoogleTLS,
		"0x1603010200010000", "0x160301", "0x16030100",
	}
	quicBlobs = []string{
		nfqws2.BlobDefaultQUIC, nfqws2.BlobGoogleQUIC,
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
	r := rng.Float64()
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
						s.Actions[i].SetParam("seqovl", strconv.Itoa(magicSeqOvls[rng.IntN(len(magicSeqOvls))]))
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
		choice := rng.IntN(100)
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
