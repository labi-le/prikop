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
	// Hard cap for mutation limits
	maxRepeats  = 10
	maxSplitPos = 8
	maxTTL      = 12
)

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

// BreedingProtocol now uses the SORTED results which are already ranked by Weighted Score (Success - Penalty)
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

	// 1. Elitism
	topCount := model.ElitesCount
	if len(parents) < topCount {
		topCount = len(parents)
	}
	for i := 0; i < topCount; i++ {
		add(parents[i].Strategy)
	}

	// 2. Adaptive Mutation
	for i := 0; i < topCount; i++ {
		p := parents[i]
		cfg := ParseConfig(p.Strategy)

		if cfg.Repeats > 4 {
			pruned := cfg
			pruned.Repeats = cfg.Repeats - 1
			add(pruned.String())

			pruned2 := cfg
			pruned2.Repeats = cfg.Repeats / 2
			if pruned2.Repeats < 1 {
				pruned2.Repeats = 1
			}
			add(pruned2.String())
		}

		numChildren := model.ElitesCount - i
		if numChildren < 3 {
			numChildren = 3
		}

		for j := 0; j < numChildren; j++ {
			mutant := cfg
			MutateFine(&mutant, discoveredBins)
			add(mutant.String())
		}
	}

	// 3. Cross-Over
	if len(parents) >= 2 {
		for i := 0; i < 10; i++ {
			idx1 := rand.Intn(topCount)
			idx2 := rand.Intn(topCount)
			if idx1 == idx2 {
				continue
			}
			p1 := ParseConfig(parents[idx1].Strategy)
			p2 := ParseConfig(parents[idx2].Strategy)

			c1 := p1
			c1.Repeats = p2.Repeats
			c1.TTL = p2.TTL
			c1.AutoTTL = p2.AutoTTL
			add(c1.String())
		}
	}

	// 4. Fill Remaining with Chaos
	remaining := populationSize - len(nextGen)
	if remaining > 0 {
		chaos := GenerateChaosPopulation(remaining, discoveredBins)
		for _, s := range chaos {
			add(s)
		}
	}

	return nextGen
}

func MutateFine(c *model.DPIConfig, discoveredBins []string) {
	r := rand.Float64()

	if c.Repeats > 4 && rand.Float64() > 0.4 {
		c.Repeats--
		return
	}
	if (c.TTL > 3 || c.AutoTTL > 3) && rand.Float64() > 0.4 {
		if c.AutoTTL > 0 {
			c.AutoTTL--
		} else {
			c.TTL--
		}
		return
	}

	if r < 0.30 {
		delta := 0
		if c.Repeats >= maxRepeats {
			delta = -1
		} else if c.Repeats <= 1 {
			delta = 1
		} else {
			delta = rand.Intn(3) - 1
		}
		c.Repeats += delta

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
	} else if r < 0.60 {
		change := rand.Intn(3) - 1
		if c.AutoTTL > 0 {
			c.AutoTTL += change
			if c.AutoTTL < 0 {
				c.AutoTTL = 0
			}
			if c.AutoTTL > maxTTL {
				c.AutoTTL = maxTTL
			}
		} else {
			c.TTL += change
			if c.TTL < 0 {
				c.TTL = 0
			}
			if c.TTL > maxTTL {
				c.TTL = maxTTL
			}
		}
	} else if r < 0.80 {
		if rand.Float64() > 0.5 && len(discoveredBins) > 0 {
			c.FakeTLS = discoveredBins[rand.Intn(len(discoveredBins))]
		} else {
			mods := []string{"none", "rndsni"}
			c.FakeTLSMod = mods[rand.Intn(len(mods))]
		}
	} else {
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
	// ... (No changes needed here, keeping strict) ...
	r := rand.Intn(9)
	switch r {
	case 0:
		c.Repeats = rand.Intn(4) + 1
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
		c.TTL = rand.Intn(5) + 1
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
		"1", "2", "3",
		"1,sniext+1", "2,sniext+1",
		"1,midsld", "2,midsld",
	}
	c.SplitPos = options[rand.Intn(len(options))]
}

// GenerateInitialPopulation now accepts explicit strategies from the phase config
func GenerateInitialPopulation(size int, discoveredBins []string, fakePath string, explicitStrategies []string) []string {
	var s []string

	// 1. Explicit Strategies (Passed from Phase configuration)
	for _, strat := range explicitStrategies {
		// Fix paths from /opt/zapret/... to container path if needed
		// We handle this here to allow raw strings in runner.go
		strat = strings.ReplaceAll(strat, "/opt/zapret/files/fake", fakePath)
		s = append(s, strat)
	}

	// 2. Base Templates (Effective everywhere, always included)
	baseTemplates := []string{
		"--dpi-desync=fake --dpi-desync-repeats=4 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=%s --dpi-desync-fake-tls-mod=rndsni",
	}
	baseFiles := []string{
		"tls_clienthello_iana_org.bin",
	}

	for i, tpl := range baseTemplates {
		fullPath := path.Join(fakePath, baseFiles[i])
		s = append(s, fmt.Sprintf(tpl, fullPath))
	}

	// 3. Simple efficient baselines (Always included)
	baseStatic := []string{
		"--dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-repeats=3",
		"--dpi-desync=ipfrag1 --dpi-desync-repeats=3",
		"--dpi-desync=multidisorder --dpi-desync-split-pos=1 --wssize=1:6",
		"--dpi-desync=fake --dpi-desync-repeats=3 --dpi-desync-fooling=badsum",
	}
	s = append(s, baseStatic...)

	// 4. Fill remaining spots with Chaos
	chaosNeeded := size - len(s)
	if chaosNeeded > 0 {
		chaos := GenerateChaosPopulation(chaosNeeded, discoveredBins)
		s = append(s, chaos...)
	}

	return Deduplicate(s)
}

func GenerateChaosPopulation(n int, discoveredBins []string) []string {
	var s []string
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < n; i++ {
		c := model.DPIConfig{}
		modes := []string{"fake", "fake", "multidisorder", "multisplit", "fakedsplit"}
		c.Mode = modes[rand.Intn(len(modes))]

		c.Repeats = rand.Intn(4) + 1

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
			c.TTL = rand.Intn(5) + 1
		} else if rand.Intn(3) == 0 {
			c.AutoTTL = rand.Intn(3) + 1
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
