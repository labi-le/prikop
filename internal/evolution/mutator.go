package evolution

import (
	"fmt"
	"math/rand"
	"prikop/internal/model"
	"strings"

	"prikop/internal/nfqws"
)

const (
	ProbResetSplit    = 0.4
	ProbResetFake     = 0.7
	ProbTimeoutRepeat = 0.4
	ProbTimeoutMode   = 0.7

	ProbMutateSplit   = 20
	ProbMutateFake    = 35
	ProbMutateMode    = 50
	ProbMutateFooling = 65
	ProbMutateTamper  = 80
	ProbMutateTTL     = 90

	ProbSecondaryMode   = 0.3
	ProbTamperEnabled   = 0.5
	ProbTamperHostCase  = 0.3
	ProbTamperMethodEol = 0.5
	ProbTamperDomCase   = 0.7
	ProbTamperHostSpell = 0.9

	ProbSplitMulti  = 0.4
	ProbSplitDouble = 0.3
	ProbSplitSeqOvl = 0.6
	ProbSplitBin    = 0.3

	ProbWSSFlip       = 0.4
	ProbGlobalRepeats = 0.3
	ProbGlobalProto   = 0.5
	ProbGlobalWSS     = 0.7

	ProbTTLAuto  = 0.6
	ProbTTLFixed = 0.9

	ProbFoolingFlip  = 0.3
	ProbFoolingRisky = 0.05

	ProbFakeTCPTLS     = 0.8
	ProbFakeTCPSynData = 0.9
	ProbFakeTCPSNI     = 0.2
	ProbFakeQUIC       = 0.5

	MaxRepeatsTCP     = 6
	MaxRepeatsUDP     = 10
	MinRepeats        = 1
	MaxRepeatsOverall = 10
)

var (
	magicSeqOvls = []int{336, 620, 109, 652, 1, 133, 500, 32, 2}
	CommonSNIs   = []string{
		"www.gosuslugi.ru", "www.sberbank.ru", "www.nalog.ru",
		"ya.ru", "vk.com", "mail.ru", "ok.ru",
		"mos.ru", "cbr.ru", "rt.com", "mapgl.2gis.com", "www.google.com", "ggpht.com",
	}
	CommonHosts = []string{
		"www.gosuslugi.ru", "www.sberbank.ru", "www.nalog.ru",
		"ya.ru", "vk.com", "mail.ru",
		"mos.ru", "cbr.ru", "mapgl.2gis.com", "ok.ru",
	}
	tamperSpells = []string{"HOst", "hoSt", "hOst", "host"}
	wssSizes     = []string{"1:6", "1:8", "1:10", "500", "800", "1400", "2048:2"}
)

type Mutator struct {
	AvailableBins []string
	Proto         string
}

func NewMutator(bins []string, proto string) *Mutator {
	return &Mutator{AvailableBins: bins, Proto: proto}
}

func (m *Mutator) Mutate(s *nfqws.Strategy) {
	m.SmartMutate(s, model.ReasonNone)
}

func (m *Mutator) SmartMutate(s *nfqws.Strategy, feedback model.FailureReason) {
	r := rand.Float64()
	m.sanitize(s)

	switch feedback {
	// === ГРУППА 1: ЖЕСТКАЯ БЛОКИРОВКА (Signature Match) ===
	// DPI распознал протокол и разорвал/подменил соединение.
	// Решение: Агрессивное изменение Fake или Split для скрытия сигнатуры.
	case model.ReasonReset,
		model.ReasonTLSNotTLS,           // Вернулась заглушка
		model.ReasonTLSOversized,        // Склейка пакетов DPI
		model.ReasonTLSRecordOverflow,   // DPI инжектировали данные или повредил запись
		model.ReasonTLSUnrecognizedName: // SNI mismatch (спуфинг от DPI)

		if r < ProbResetSplit {
			m.mutateSplit(s) // Меняем точку разрыва (смещаем SNI)
		} else if r < ProbResetFake {
			m.mutateFake(s) // Меняем Fake (сигнатуру мусора)
		} else {
			m.mutateTamper(s) // Включаем tamper (изменение заголовков)
		}

	// === ГРУППА 2: ПОТЕРЯ ПАКЕТОВ / ТАЙМАУТЫ ===
	// Пакеты не доходят или дропаются тихо.
	// Решение: Изменение параметров доставки (TTL, Repeats, Mode).
	case model.ReasonTimeout,
		model.ReasonTLSHandshake,
		model.ReasonTLSInternal:

		if r < ProbTimeoutRepeat {
			m.mutateRepeats(s) // Больше повторов
		} else if r < ProbTimeoutMode {
			m.mutateMode(s) // Смена режима доставки (fake -> split)
		} else {
			m.mutateTTL(s) // Проблема в TTL
		}

	// === ГРУППА 3: MITM / ВМЕШАТЕЛЬСТВО (Intervention) ===
	// DPI пытается вклиниться в рукопожатие, понизить версию или подменить сертификат.
	// Решение: Ломать синхронизацию (SynAck), Disorder (путать сборщик DPI), WSS.
	case model.ReasonTLSALPN,
		model.ReasonTLSVersion,
		model.ReasonTLSCipherSuite, // <--- MITM: Сервер выбрал шифр, который клиент не предлагал
		model.ReasonTLSDowngrade,
		model.ReasonTLSCertUnknown,
		model.ReasonTLSCertMismatch,
		model.ReasonTLSCertExpired, // MITM: просроченный сертификат
		model.ReasonTLSBadSignature,
		model.ReasonTLSIllegalParam, // MITM: повреждение полей handshake
		model.ReasonTLSSessionID:

		if !strings.Contains(s.Mode, "synack") && r < 0.4 {
			s.Mode += ",synack" // Ломаем начало соединения
		} else if r < 0.7 {
			m.mutateWSS(s) // Форсируем сплит ответа сервера
		} else {
			// Disorder эффективен против MITM, так как DPI не может собрать поток
			if !strings.Contains(s.Mode, "disorder") {
				s.Mode = strings.ReplaceAll(s.Mode, "split", "disorder")
				if !strings.Contains(s.Mode, "disorder") {
					s.Mode = "multidisorder"
				}
				m.mutateSplit(s)
			} else {
				// Если уже disorder, меняем параметры перекрытия
				s.Split.SeqOvl = magicSeqOvls[rand.Intn(len(magicSeqOvls))]
			}
		}

	// === ГРУППА 4: ПОВРЕЖДЕНИЕ ДАННЫХ (Corruption) ===
	// Мы сломали пакет так, что сервер или клиент не могут его прочитать.
	// Решение: УПРОЩЕНИЕ (Simplification). Откат агрессивных методов.
	case model.ReasonTLSBadMAC,
		model.ReasonTLSDecrypt,
		model.ReasonTLSDecode,
		model.ReasonTLSAlertUnexpected:

		m.mutateSimplify(s)

	// === ГРУППА 5: ШЕЙПИНГ ===
	case model.ReasonThrottle:
		m.mutateWSS(s) // Меняем размер окна, чтобы сбить шейпер
		if r < 0.5 {
			m.mutateSplit(s)
		}

	// === DEFAULT / RANDOM ===
	default:
		choice := rand.Intn(100)
		switch {
		case choice < ProbMutateSplit:
			m.mutateSplit(s)
		case choice < ProbMutateFake:
			m.mutateFake(s)
		case choice < ProbMutateMode:
			m.mutateMode(s)
			if strings.Contains(s.Mode, "fake") {
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

// mutateSimplify уменьшает агрессивность стратегии, если она вызывает ошибки протокола
func (m *Mutator) mutateSimplify(s *nfqws.Strategy) {
	// 1. Отключаем BadSum/BadSeq (частая причина поломок за NAT)
	s.Fooling.BadSum = false
	s.Fooling.BadSeq = false

	// 2. Disorder -> Split (Disorder часто ломает стейт TLS 1.3)
	if strings.Contains(s.Mode, "disorder") {
		s.Mode = strings.ReplaceAll(s.Mode, "multidisorder", "multisplit")
		s.Mode = strings.ReplaceAll(s.Mode, "fakeddisorder", "fakedsplit")
		s.Mode = strings.ReplaceAll(s.Mode, "disorder", "split")
	}

	// 3. Уменьшаем перекрытие (SeqOvl), если оно есть
	if s.Split.SeqOvl > 0 {
		s.Split.SeqOvl = 0 // Выключаем перекрытие, так как оно может портить данные
	}

	// 4. Сбрасываем repeats до минимума, чтобы снизить шум
	s.Repeats = 1

	// 5. Если есть фейк, пробуем сделать его стандартным
	if strings.Contains(s.Mode, "fake") {
		s.Fake.TlsMod = "" // Убираем модификаторы фейка
	}
}

func (m *Mutator) sanitize(s *nfqws.Strategy) {
	modes := strings.Split(s.Mode, ",")
	var p0, p1, p2 []string

	for _, raw := range modes {
		mode := strings.TrimSpace(raw)
		if mode == "" {
			continue
		}

		switch mode {
		case "syndata", "synack":
			p0 = append(p0, mode)
		case "hopbyhop", "destopt", "ipfrag1":
			// Explicitly ignore IPv6 specific modes
			continue
		case "fake", "fakeknown", "rst", "rstack":
			p1 = append(p1, mode)
		case "multisplit", "multidisorder", "fakedsplit", "fakeddisorder",
			"hostfakesplit", "ipfrag2", "udplen", "tamper":
			p2 = append(p2, mode)
		default:
			p2 = append(p2, mode)
		}
	}

	var finalModes []string
	if len(p0) > 0 {
		finalModes = append(finalModes, p0[0])
	}
	if len(p1) > 0 {
		finalModes = append(finalModes, p1[0])
	}
	if len(p2) > 0 {
		finalModes = append(finalModes, p2[0])
	}

	s.Mode = strings.Join(finalModes, ",")

	isFake := strings.Contains(s.Mode, "fake")
	isSplit := strings.Contains(s.Mode, "split") || strings.Contains(s.Mode, "disorder")
	isHostFake := strings.Contains(s.Mode, "hostfakesplit")
	isTamper := strings.Contains(s.Mode, "tamper")
	isSyndata := strings.Contains(s.Mode, "syndata")
	isUdpLen := strings.Contains(s.Mode, "udplen")

	if !isFake && !isSyndata {
		s.Fake = nfqws.FakeOptions{}
	} else {
		isClientHello := strings.Contains(s.Fake.TLS, "clienthello")
		isDTLS := strings.Contains(s.Fake.TLS, "dtls")
		isKyber := strings.Contains(s.Fake.TLS, "kyber")

		if s.Fake.TlsMod != "" {
			if !isClientHello || isDTLS || isKyber {
				s.Fake.TlsMod = ""
			}
		}

		if s.Fake.TLS == "" && s.Fake.Quic == "" && s.Fake.UnknownUdp == "" && s.Fake.SynData == "" {
			m.mutateFake(s)
		}

		if m.Proto == "udp" {
			s.Fake.TLS = ""
		} else {
			s.Fake.Quic = ""
			s.Fake.UnknownUdp = ""
		}
	}

	if !isSplit && !isHostFake {
		s.Split = nfqws.SplitOptions{}
	}
	if !isTamper {
		s.Tamper = nfqws.TamperOptions{}
	}
	if !isUdpLen {
		s.UdpLen = nfqws.UdpLenOptions{}
	}
	if isHostFake {
		if s.Split.HostMod == "" {
			s.Split.HostMod = "host=" + CommonHosts[rand.Intn(len(CommonHosts))]
		}
	}

	if s.Repeats < MinRepeats {
		s.Repeats = MinRepeats
	}
	if s.Repeats > MaxRepeatsOverall {
		s.Repeats = MaxRepeatsOverall
	}

	s.Fooling.HopByHop = false
	s.Fooling.HopByHop2 = false
}

func (m *Mutator) mutateMode(s *nfqws.Strategy) {
	var baseModes []string
	var secondaryModes []string

	if m.Proto == "tcp" {
		baseModes = []string{
			"fake", "multisplit", "multidisorder",
			"hostfakesplit", "syndata",
		}
		secondaryModes = []string{"tamper", "rst"}
	} else {
		baseModes = []string{"fake", "multisplit", "udplen", "ipfrag2"}
		secondaryModes = []string{"udplen", "ipfrag2"}
	}

	newMode := baseModes[rand.Intn(len(baseModes))]

	if rand.Float64() < ProbSecondaryMode && len(secondaryModes) > 0 {
		sec := secondaryModes[rand.Intn(len(secondaryModes))]
		if !strings.Contains(newMode, sec) {
			newMode += "," + sec
		}
	}
	s.Mode = newMode
}

func (m *Mutator) mutateTamper(s *nfqws.Strategy) {
	isP2 := strings.Contains(s.Mode, "split") ||
		strings.Contains(s.Mode, "disorder") ||
		strings.Contains(s.Mode, "ipfrag2") ||
		strings.Contains(s.Mode, "udplen")

	if isP2 {
		return
	}

	if !strings.Contains(s.Mode, "tamper") {
		if rand.Float64() < ProbTamperEnabled {
			if s.Mode == "" {
				s.Mode = "tamper"
			} else {
				s.Mode += ",tamper"
			}
		} else {
			return
		}
	}

	r := rand.Float64()
	if r < ProbTamperHostCase {
		s.Tamper.HostCase = !s.Tamper.HostCase
	} else if r < ProbTamperMethodEol {
		s.Tamper.MethodEol = !s.Tamper.MethodEol
	} else if r < ProbTamperDomCase {
		s.Tamper.DomCase = !s.Tamper.DomCase
	} else if r < ProbTamperHostSpell {
		s.Tamper.HostSpell = tamperSpells[rand.Intn(len(tamperSpells))]
	} else {
		s.Tamper.HostNoSpace = !s.Tamper.HostNoSpace
	}
}

func (m *Mutator) mutateSplit(s *nfqws.Strategy) {
	if strings.Contains(s.Mode, "hostfakesplit") {
		mod := CommonHosts[rand.Intn(len(CommonHosts))]
		s.Split.HostMod = "host=" + mod
		s.Split.SeqOvl = 0
		return
	}

	// ЭВРИСТИКА: Увеличиваем вероятность позиций, связанных с SNI и Host.
	// DPI часто ломается именно на разрыве заголовков.
	markers := []string{
		"midsld", "sniext", "endsld", // Высокий приоритет (разрыв внутри домена/SNI)
		"method", "host", // Средний приоритет
		"2", "3", // Низкий приоритет (магические числа)
	}

	genPos := func() string {
		marker := markers[rand.Intn(len(markers))]

		// Для простых числовых маркеров возвращаем как есть
		if len(marker) < 3 {
			return marker
		}

		// Добавляем микро-смещение, чтобы "гулять" вокруг маркера (например, sniext+1)
		offset := rand.Intn(5) - 2 // от -2 до +2
		if offset == 0 {
			return marker
		}
		if offset > 0 {
			return fmt.Sprintf("%s+%d", marker, offset)
		}
		return fmt.Sprintf("%s%d", marker, offset) // offset отрицательный, знак уже есть
	}

	// Для multisplit/multidisorder часто выгодно разорвать пакет в самом начале (1) и в середине (SNI)
	if (strings.Contains(s.Mode, "multisplit") || strings.Contains(s.Mode, "multidisorder")) && rand.Float64() < ProbSplitMulti {
		s.Split.Pos = "1," + genPos()
	} else if rand.Float64() < ProbSplitDouble {
		// Двойной разрыв в случайных местах
		s.Split.Pos = genPos() + "," + genPos()
	} else {
		s.Split.Pos = genPos()
	}

	// SeqOvl - важный параметр для disorder. Малые значения часто работают лучше.
	if rand.Float64() < ProbSplitSeqOvl {
		s.Split.SeqOvl = magicSeqOvls[rand.Intn(len(magicSeqOvls))]
	} else {
		s.Split.SeqOvl = 1 + rand.Intn(5)
	}

	if rand.Float64() < ProbSplitBin {
		s.Split.Pattern = m.AvailableBins[rand.Intn(len(m.AvailableBins))]
	}
}

func (m *Mutator) mutateRepeats(s *nfqws.Strategy) {
	delta := rand.Intn(3) - 1
	s.Repeats += delta
	maxRepeats := MaxRepeatsTCP
	if m.Proto == "udp" {
		maxRepeats = MaxRepeatsUDP
	}
	if s.Repeats > maxRepeats {
		s.Repeats = maxRepeats
	}
	if s.Repeats < MinRepeats {
		s.Repeats = MinRepeats
	}
}

func (m *Mutator) mutateWSS(s *nfqws.Strategy) {
	if rand.Float64() < ProbWSSFlip {
		s.WSS.Enabled = !s.WSS.Enabled
	}
	if s.WSS.Enabled {
		s.WSS.Value = wssSizes[rand.Intn(len(wssSizes))]
	}
}

func (m *Mutator) mutateGlobal(s *nfqws.Strategy) {
	r := rand.Float64()
	if r < ProbGlobalRepeats {
		m.mutateRepeats(s)
	} else if r < ProbGlobalProto {
		if m.Proto == "udp" {
			s.AnyProtocol = !s.AnyProtocol
			if s.AnyProtocol {
				s.Cutoff = "d2"
			} else {
				s.Cutoff = ""
			}
		}
	} else if r < ProbGlobalWSS {
		m.mutateWSS(s)
	} else {
		if m.Proto == "udp" {
			inc := rand.Intn(32) - 16
			if inc == 0 {
				inc = 2
			}
			s.UdpLen.Increment = inc
		}
	}
}

func (m *Mutator) mutateTTL(s *nfqws.Strategy) {
	r := rand.Float64()
	if r < ProbTTLAuto {
		s.TTL.Auto = 1 + rand.Intn(12)
		s.TTL.Fixed = 0
	} else if r < ProbTTLFixed {
		s.TTL.Fixed = 1 + rand.Intn(10)
		s.TTL.Auto = 0
	} else {
		s.TTL.Auto = 0
		s.TTL.Fixed = 0
	}
}

func (m *Mutator) mutateFooling(s *nfqws.Strategy) {
	// Conservative mutations: Low probability for breaking changes
	flip := func(current bool, prob float64) bool {
		if rand.Float64() < prob {
			return !current
		}
		return current
	}

	s.Fooling.Md5Sig = flip(s.Fooling.Md5Sig, ProbFoolingFlip)
	// SIGNIFICANTLY REDUCED PROBABILITY FOR BADSUM/BADSEQ
	// Only 5% chance to flip them on/off, heavily biased towards OFF via Engine penalty
	s.Fooling.BadSum = flip(s.Fooling.BadSum, ProbFoolingRisky)
	s.Fooling.BadSeq = flip(s.Fooling.BadSeq, ProbFoolingRisky)

	s.Fooling.Datanoack = flip(s.Fooling.Datanoack, ProbFoolingFlip)
	s.Fooling.Ts = flip(s.Fooling.Ts, ProbFoolingFlip)

	s.Fooling.HopByHop = false
	s.Fooling.HopByHop2 = false
}

func (m *Mutator) pickStrict(keywords ...string) string {
	var candidates []string
	for _, b := range m.AvailableBins {
		for _, k := range keywords {
			if strings.Contains(b, k) {
				candidates = append(candidates, b)
				break
			}
		}
	}
	if len(candidates) > 0 {
		return candidates[rand.Intn(len(candidates))]
	}
	return ""
}

func (m *Mutator) pickAny() string {
	return m.AvailableBins[rand.Intn(len(m.AvailableBins))]
}

func (m *Mutator) mutateFake(s *nfqws.Strategy) {
	if m.Proto == "tcp" {
		r := rand.Float64()
		tlsBin := m.pickStrict("clienthello")

		if tlsBin != "" && !strings.Contains(tlsBin, "dtls") && r < ProbFakeTCPTLS {
			s.Fake.TLS = tlsBin
			if strings.Contains(tlsBin, "kyber") {
				s.Fake.TlsMod = ""
			} else {
				mods := []string{"rnd", "rndsni", "rnd,dupsid", "padencap", ""}
				s.Fake.TlsMod = mods[rand.Intn(len(mods))]
				if rand.Float64() < ProbFakeTCPSNI {
					sni := CommonSNIs[rand.Intn(len(CommonSNIs))]
					s.Fake.TlsMod = "sni=" + sni
				}
			}
		} else {
			if r < ProbFakeTCPSynData {
				s.Fake.SynData = "0x00"
			} else {
				s.Fake.TLS = m.pickAny()
			}
			s.Fake.TlsMod = ""
		}
	} else {
		r := rand.Float64()
		if r < ProbFakeQUIC {
			quicBin := m.pickStrict("quic")
			if quicBin != "" && !strings.Contains(quicBin, "short") {
				s.Fake.Quic = quicBin
				s.Fake.TlsMod = "rnd"
				s.Fake.UnknownUdp = ""
				return
			}
		}
		s.Fake.UnknownUdp = m.pickStrict("wireguard", "dht", "stun", "512")
		if s.Fake.UnknownUdp == "" {
			s.Fake.UnknownUdp = m.pickAny()
		}
		s.Fake.Quic = ""
	}
}
