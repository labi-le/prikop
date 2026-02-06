package genes

import (
	"fmt"
	"math/rand"
	"path"
	"prikop/internal/model"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxRepeats  = 20
	maxSplitPos = 8
	maxTTL      = 12
)

// ParseConfig ... (без изменений)
func ParseConfig(s string) model.DPIConfig {
	c := model.DPIConfig{Mode: "fake", Repeats: 1, FakeTLSMod: "none"}

	if strings.Contains(s, "split2") || strings.Contains(s, "multisplit") {
		c.Mode = "multisplit"
	} else if strings.Contains(s, "disorder2") || strings.Contains(s, "multidisorder") {
		c.Mode = "multidisorder"
	} else if strings.Contains(s, "fakedsplit") {
		c.Mode = "fakedsplit"
	} else if strings.Contains(s, "ipfrag1") {
		c.Mode = "ipfrag1"
	} else if strings.Contains(s, "hostfakesplit") {
		c.Mode = "hostfakesplit"
	}

	if match := regexp.MustCompile(`--dpi-desync-repeats=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.Repeats, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-ttl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.TTL, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-autottl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.AutoTTL, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-split-pos=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.SplitPos = match[1]
	}
	if match := regexp.MustCompile(`--dpi-desync-split-seqovl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.SplitSeqOvl, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-fooling=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.Fooling = match[1]
	}
	if match := regexp.MustCompile(`--dpi-desync-fake-tls=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.FakeTLS = match[1]
	}
	if match := regexp.MustCompile(`--dpi-desync-fake-tls-mod=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.FakeTLSMod = match[1]
	}
	if match := regexp.MustCompile(`--wssize=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.Wssize = match[1]
	}
	if match := regexp.MustCompile(`--dpi-desync-cutoff=([^ ]+)`).FindStringSubmatch(s); len(match) > 1 {
		c.Cutoff = match[1]
	}
	if strings.Contains(s, "--dpi-desync-any-protocol") {
		c.AnyProtocol = true
	}
	return c
}

// BreedingProtocol executes the evolutionary step with ADAPTIVE LOGIC
func BreedingProtocol(parents []model.StrategyResult, populationSize int, discoveredBins []string) []string {
	var nextGen []string
	seen := make(map[string]struct{})
	rand.Seed(time.Now().UnixNano())

	add := func(s string) {
		s = strings.TrimSpace(s)
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			nextGen = append(nextGen, s)
		}
	}

	// 1. Calculate the "Fitness Stability" of the best parent
	// If the best parent is performing well (>60%), we reduce chaos significantly.
	isStable := false
	if len(parents) > 0 {
		best := parents[0]
		if best.TotalCount > 0 {
			rate := (best.SuccessCount * 100) / best.TotalCount
			if rate > 60 {
				isStable = true
			}
		}
	}

	// 2. Elitism: Keep parents
	for _, p := range parents {
		add(p.Strategy)
	}

	// 3. Adaptive Mutation Strategy
	fineMutationsPerParent := 6
	if isStable {
		// If we are stable, increase fine mutations to saturate the population with variations of the good gene
		fineMutationsPerParent = 12
	}

	// High Fidelity Mutations (Fine Tuning)
	for _, p := range parents {
		cfg := ParseConfig(p.Strategy)
		for i := 0; i < fineMutationsPerParent; i++ {
			mutant := cfg
			MutateFine(&mutant, discoveredBins)
			add(mutant.String())
		}
	}

	// Cross-Over
	if len(parents) >= 2 {
		for i := 0; i < len(parents)-1; i++ {
			p1 := ParseConfig(parents[i].Strategy)
			p2 := ParseConfig(parents[rand.Intn(len(parents))].Strategy)

			c1 := p1
			c1.TTL = p2.TTL
			c1.AutoTTL = p2.AutoTTL
			c1.Wssize = p2.Wssize
			add(c1.String())

			c2 := p1
			c2.SplitPos = p2.SplitPos
			c2.SplitSeqOvl = p2.SplitSeqOvl
			add(c2.String())
		}
	}

	// 4. Fill Remaining Spots
	remaining := populationSize - len(nextGen)
	if remaining > 0 {
		if isStable {
			// CONSERVATIVE MODE: Fill with more fine mutations of the BEST parent only
			// We discard "Chaos" because we already have a working baseline.
			bestCfg := ParseConfig(parents[0].Strategy)
			for i := 0; i < remaining; i++ {
				m := bestCfg
				// Apply slightly more aggressive fine mutation
				MutateFine(&m, discoveredBins)
				if rand.Float64() > 0.7 {
					MutateWild(&m) // Small chance of wild mutation on good gene
				}
				add(m.String())
			}
		} else {
			// EXPLORATION MODE: We are lost, inject pure chaos to find a path
			chaos := GenerateChaosPopulation(remaining, discoveredBins)
			for _, s := range chaos {
				add(s)
			}
		}
	}

	return nextGen
}

// ... (MutateFine, MutateWild, randomSplitPos, GenerateInitialPopulation, GenerateChaosPopulation, Deduplicate без изменений)
func MutateFine(c *model.DPIConfig, discoveredBins []string) {
	r := rand.Float64()

	if r < 0.25 {
		c.Repeats += rand.Intn(3) - 1
		if c.Repeats < 1 {
			c.Repeats = 1
		}
		if c.Repeats > maxRepeats {
			c.Repeats = maxRepeats
		}
		if val, err := strconv.Atoi(c.SplitPos); err == nil && val > 0 {
			val += rand.Intn(3) - 1
			if val < 1 {
				val = 1
			}
			if val > maxSplitPos {
				val = maxSplitPos
			}
			c.SplitPos = strconv.Itoa(val)
		}
	}
	if r >= 0.25 && r < 0.50 {
		if c.AutoTTL > 0 {
			c.AutoTTL += rand.Intn(3) - 1
			if c.AutoTTL < 0 {
				c.AutoTTL = 0
			}
			if c.AutoTTL > maxTTL {
				c.AutoTTL = maxTTL
			}
		} else {
			c.TTL += rand.Intn(3) - 1
			if c.TTL < 0 {
				c.TTL = 0
			}
			if c.TTL > maxTTL {
				c.TTL = maxTTL
			}
		}
	}
	if r >= 0.50 && r < 0.75 {
		if rand.Float64() > 0.5 && len(discoveredBins) > 0 {
			c.FakeTLS = discoveredBins[rand.Intn(len(discoveredBins))]
		} else {
			if c.FakeTLSMod == "none" {
				c.FakeTLSMod = "rndsni"
			} else if c.FakeTLSMod == "rndsni" {
				c.FakeTLSMod = "none"
			}
		}
	}
	if r >= 0.75 {
		if c.Wssize == "" {
			c.Wssize = "1:6"
		} else {
			c.Wssize = ""
		}
		if c.SplitSeqOvl == 0 {
			c.SplitSeqOvl = 1
		} else {
			c.SplitSeqOvl = 0
		}
	}
}

func MutateWild(c *model.DPIConfig) {
	r := rand.Intn(9)
	switch r {
	case 0:
		c.Repeats = rand.Intn(maxRepeats) + 1
	case 1:
		modes := []string{"fake", "multidisorder", "multisplit", "fakedsplit", "ipfrag1"}
		c.Mode = modes[rand.Intn(len(modes))]
		if c.Mode == "multisplit" || c.Mode == "multidisorder" {
			randomSplitPos(c)
		}
	case 2:
		mods := []string{"none", "rnd", "rndsni"}
		c.FakeTLSMod = mods[rand.Intn(len(mods))]
	case 3:
		cutoffs := []string{"", "d2", "n2"}
		c.Cutoff = cutoffs[rand.Intn(len(cutoffs))]
	case 4:
		c.AnyProtocol = !c.AnyProtocol
	case 5:
		c.AutoTTL = 0
		c.TTL = rand.Intn(maxTTL)
	case 6:
		c.SplitSeqOvl = rand.Intn(2)
	case 7:
		if c.Wssize == "" {
			c.Wssize = "1:6"
		} else {
			c.Wssize = ""
		}
	case 8:
		randomSplitPos(c)
	}
}

func randomSplitPos(c *model.DPIConfig) {
	options := []string{
		"1", "2", "3", "4",
		"1,sniext+1", "2,sniext+1",
		"1,midsld", "2,midsld",
		"1,0x0001",
	}
	c.SplitPos = options[rand.Intn(len(options))]
}

func GenerateInitialPopulation(size int, discoveredBins []string, fakePath string) []string {
	var s []string
	s = append(s, "--dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1 --dpi-desync-split-seqovl=1")
	s = append(s, "--dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=2")

	baseTemplates := []string{
		"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=%s --dpi-desync-fake-tls-mod=none",
		"--dpi-desync=fake --dpi-desync-repeats=4 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=%s --dpi-desync-fake-tls-mod=rndsni",
	}
	baseFiles := []string{
		"tls_clienthello_www_google_com.bin",
		"tls_clienthello_iana_org.bin",
	}

	for i, tpl := range baseTemplates {
		fullPath := path.Join(fakePath, baseFiles[i])
		s = append(s, fmt.Sprintf(tpl, fullPath))
	}

	baseStatic := []string{
		"--dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-repeats=3",
		"--dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=5",
		"--dpi-desync=ipfrag1 --dpi-desync-repeats=3",
		"--dpi-desync=multidisorder --dpi-desync-split-pos=1 --wssize=1:6",
	}
	s = append(s, baseStatic...)

	chaos := GenerateChaosPopulation(size-len(s), discoveredBins)
	s = append(s, chaos...)
	return Deduplicate(s)
}

func GenerateChaosPopulation(n int, discoveredBins []string) []string {
	var s []string
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < n; i++ {
		c := model.DPIConfig{}
		modes := []string{"fake", "fake", "multidisorder", "multisplit", "fakedsplit"}
		c.Mode = modes[rand.Intn(len(modes))]
		c.Repeats = rand.Intn(maxRepeats-1) + 1

		if c.Mode == "fake" || c.Mode == "fakedsplit" {
			fList := []string{"ts", "md5sig", "badsum", "datanoack"}
			c.Fooling = fList[rand.Intn(len(fList))]

			if len(discoveredBins) > 0 {
				c.FakeTLS = discoveredBins[rand.Intn(len(discoveredBins))]
			}
			mods := []string{"none", "rnd", "rndsni"}
			c.FakeTLSMod = mods[rand.Intn(len(mods))]
		}

		if c.Mode == "multisplit" || c.Mode == "multidisorder" {
			randomSplitPos(&c)
			if rand.Intn(2) == 0 {
				c.SplitSeqOvl = 1
			}
		}

		if rand.Intn(3) == 0 {
			c.Wssize = "1:6"
		}
		if rand.Intn(2) == 0 {
			c.TTL = rand.Intn(maxTTL-1) + 1
		} else {
			c.AutoTTL = rand.Intn(maxTTL/2) + 1
		}
		s = append(s, c.String())
	}
	return s
}

func Deduplicate(s []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range s {
		v = strings.TrimSpace(strings.ReplaceAll(v, "  ", " "))
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
