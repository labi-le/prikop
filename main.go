package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const (
	QueueNum  = "200"
	ImageName = "prikop:latest"

	ContainerTimeout = 10 * time.Second // Faster timeout
	MaxWorkers       = 50               // Maximize concurrency
	MaxTotalAttempts = 8000
	OkThresholdBytes = 64 * 1024
	CheckTimeout     = 2000 * time.Millisecond

	// Evolutionary Params
	MaxGenerations    = 40
	TargetSuccessRate = 26  // We want 100%
	PopulationSize    = 100 // Large population for diverse genes
	ElitesCount       = 8
)

var DiscoveredBins []string
var GlobalBest StrategyResult

type Target struct {
	ID       string
	Provider string
	URL      string
	Times    int
}

var testSuite = []Target{
	{ID: "US.CF-01", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://img.wzstats.gg/cleaver/gunFullDisplay"},
	{ID: "US.CF-02", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://genshin.jmp.blue/characters/all#"},
	{ID: "US.CF-03", Provider: "🇺🇸 Cloudflare", Times: 1, URL: "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31"},
	{ID: "US.CF-04", Provider: "🇨🇦 Cloudflare", Times: 1, URL: "https://www.bigcartel.com/"},
	{ID: "US.DO-01", Provider: "🇺🇸 DigitalOcean", Times: 2, URL: "https://genderize.io/"},
	{ID: "DE.HE-01", Provider: "🇩🇪 Hetzner", Times: 1, URL: "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp"},
	{ID: "DE.HE-02", Provider: "🇩🇪 Hetzner", Times: 1, URL: "https://accesorioscelular.com/tienda/css/plugins.css"},
	{ID: "FI.HE-01", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://251b5cd9.nip.io/1MB.bin"},
	{ID: "FI.HE-02", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://nioges.com/libs/fontawesome/webfonts/fa-solid-900.woff2"},
	{ID: "FI.HE-03", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://5fd8bdae.nip.io/1MB.bin"},
	{ID: "FI.HE-04", Provider: "🇫🇮 Hetzner", Times: 1, URL: "https://5fd8bca5.nip.io/1MB.bin"},
	{ID: "FR.OVH-01", Provider: "🇫🇷 OVH", Times: 1, URL: "https://eu.api.ovh.com/console/rapidoc-min.js"},
	{ID: "FR.OVH-02", Provider: "🇫🇷 OVH", Times: 1, URL: "https://ovh.sfx.ovh/10M.bin"},
	{ID: "SE.OR-01", Provider: "🇸🇪 Oracle", Times: 1, URL: "https://oracle.sfx.ovh/10M.bin"},
	{ID: "DE.AWS-01", Provider: "🇩🇪 AWS", Times: 1, URL: "https://www.getscope.com/assets/fonts/fa-solid-900.woff2"},
	{ID: "US.AWS-01", Provider: "🇺🇸 AWS", Times: 1, URL: "https://corp.kaltura.com/wp-content/cache/min/1/wp-content/themes/airfleet/dist/styles/theme.css"},
	{ID: "US.GC-01", Provider: "🇺🇸 Google Cloud", Times: 1, URL: "https://api.usercentrics.eu/gvl/v3/en.json"},
	{ID: "US.FST-01", Provider: "🇺🇸 Fastly", Times: 1, URL: "https://www.jetblue.com/footer/footer-element-es2015.js"},
	{ID: "CA.FST-01", Provider: "🇨🇦 Fastly", Times: 1, URL: "https://ssl.p.jwpcdn.com/player/v/8.40.5/bidding.js"},
	{ID: "US.AKM-01", Provider: "🇺🇸 Akamai", Times: 1, URL: "https://www.roxio.com/static/roxio/images/products/creator/nxt9/call-action-footer-bg.jpg"},
	{ID: "PL.AKM-01", Provider: "🇵🇱 Akamai", Times: 1, URL: "https://media-assets.stryker.com/is/image/stryker/gateway_1?$max_width_1410$"},
	{ID: "US.CDN77-01", Provider: "🇺🇸 CDN77", Times: 1, URL: "https://cdn.eso.org/images/banner1920/eso2520a.jpg"},
	{ID: "FR.CNTB-01", Provider: "🇫🇷 Contabo", Times: 1, URL: "https://xdmarineshop.gr/index.php?route=index"},
	{ID: "NL.SW-01", Provider: "🇳🇱 Scaleway", Times: 1, URL: "https://www.velivole.fr/img/header.jpg"},
	{ID: "US.CNST-01", Provider: "🇺🇸 Constant", Times: 1, URL: "https://cdn.xuansiwei.com/common/lib/font-awesome/4.7.0/fontawesome-webfont.woff2?v=4.7.0"},
}

type WorkerResult struct {
	Success      bool   `json:"success"`
	Code         int    `json:"code"`
	Error        string `json:"error,omitempty"`
	SuccessCount int    `json:"success_count"`
	TotalCount   int    `json:"total_count"`
}

type StrategyResult struct {
	Strategy     string
	Duration     time.Duration
	WorkerResult // Embed
	SystemLogs   string
}

type DPIConfig struct {
	Mode        string
	Repeats     int
	Fooling     string
	FakeTLS     string
	FakeTLSMod  string
	TTL         int
	AutoTTL     int
	SplitPos    int
	SplitSeqOvl int
	Wssize      string
	AnyProtocol bool
	Cutoff      string
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "worker" {
		runWorkerMode(os.Args[2])
	} else {
		runOrchestratorMode()
	}
}

// --- Worker Logic ---

func runWorkerMode(strategy string) {
	log.SetOutput(os.Stderr)
	if strategy == "" {
		fatalJSON("No strategy provided in args")
	}

	cmds := [][]string{
		{"iptables", "-t", "mangle", "-F"},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", QueueNum},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", QueueNum},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fatalJSON(fmt.Sprintf("iptables error: %v | out: %s", err, string(out)))
		}
	}

	nfqwsArgs := strings.Fields(fmt.Sprintf("--qnum=%s %s", QueueNum, strategy))
	cmd := exec.Command("nfqws", nfqwsArgs...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		fatalJSON(fmt.Sprintf("nfqws start failed: %v", err))
	}

	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-doneCh:
		fatalJSON(fmt.Sprintf("nfqws crashed immediately: %v | Logs: %s", err, stderrBuf.String()))
	default:
	}

	httpClient := &http.Client{
		Timeout: CheckTimeout + 1*time.Second,
		Transport: &http.Transport{
			DisableKeepAlives:   false,
			TLSHandshakeTimeout: 2 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	var wg sync.WaitGroup
	var successCount int32
	var totalChecks int32
	sem := make(chan struct{}, 8)

	for _, t := range testSuite {
		for i := 0; i < t.Times; i++ {
			wg.Add(1)
			totalChecks++
			targetURL := t.URL
			if strings.Contains(targetURL, "?") {
				targetURL += fmt.Sprintf("&t=%d", time.Now().UnixNano())
			} else {
				targetURL += fmt.Sprintf("?t=%d", time.Now().UnixNano())
			}

			go func(u string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				select {
				case <-doneCh:
					return
				default:
				}

				ctx, cancel := context.WithTimeout(context.Background(), CheckTimeout)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
				if err != nil {
					return
				}
				req.Header.Set("Cache-Control", "no-store")
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

				resp, err := httpClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				buf := make([]byte, 8192)
				var received int
				var ok bool
				for {
					n, rErr := resp.Body.Read(buf)
					received += n
					if received >= OkThresholdBytes {
						ok = true
						break
					}
					if rErr != nil {
						break
					}
				}
				if ok {
					atomic.AddInt32(&successCount, 1)
				}
			}(targetURL)
		}
	}
	wg.Wait()

	select {
	case err := <-doneCh:
		fatalJSON(fmt.Sprintf("nfqws crashed: %v | Logs: %s", err, stderrBuf.String()))
	default:
	}

	finalSuccess := int(atomic.LoadInt32(&successCount))
	res := WorkerResult{
		Success:      finalSuccess > 0,
		Code:         200,
		SuccessCount: finalSuccess,
		TotalCount:   int(totalChecks),
	}
	if finalSuccess == 0 {
		res.Error = "No targets passed"
	}
	printJSON(res)
}

func printJSON(res WorkerResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(res)
}

func fatalJSON(msg string) {
	printJSON(WorkerResult{Success: false, Error: msg})
	os.Exit(1)
}

// --- Orchestrator Logic ---

func runOrchestratorMode() {
	ctx := context.Background()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Docker client failed: %v", err)
	}
	defer cli.Close()

	fmt.Println(">>> 🔎 Discovering .bin files inside the container...")
	bins, err := discoverBinFiles(ctx, cli)
	if err != nil || len(bins) == 0 {
		log.Fatalf("❌ FATAL: Failed to discover bins or no bins found. Err: %v", err)
	}
	DiscoveredBins = bins
	fmt.Printf(">>> ✅ Found %d .bin files.\n", len(DiscoveredBins))

	history := make(map[string]bool)
	var allResults []StrategyResult
	totalAttempts := 0

	currentGenStrats := generateInitialPopulation(PopulationSize)

	fmt.Printf("\n>>> 🧬 EVOLUTION STARTED (Max Gens: %d, Target: %d)\n", MaxGenerations, TargetSuccessRate)

	for gen := 0; gen < MaxGenerations; gen++ {
		fmt.Printf("\n>>> 🧬 GENERATION %d (%d strategies)\n", gen, len(currentGenStrats))

		results, _ := executeBatch(ctx, cli, currentGenStrats, history, &totalAttempts)
		allResults = append(allResults, results...)

		sort.Slice(results, func(i, j int) bool {
			if results[i].SuccessCount != results[j].SuccessCount {
				return results[i].SuccessCount > results[j].SuccessCount
			}
			if len(results[i].Strategy) != len(results[j].Strategy) {
				return len(results[i].Strategy) < len(results[j].Strategy)
			}
			return results[i].Duration < results[j].Duration
		})

		// Analysis
		var avgScore float64
		var maxScore int
		for _, r := range results {
			avgScore += float64(r.SuccessCount)
			if r.SuccessCount > maxScore {
				maxScore = r.SuccessCount
			}
		}
		if len(results) > 0 {
			avgScore /= float64(len(results))
		}
		fmt.Printf(">>> 📊 Gen Stats: Max=%d, Avg=%.1f\n", maxScore, avgScore)

		// Update Global Best
		if len(results) > 0 {
			genBest := results[0]
			if genBest.SuccessCount > GlobalBest.SuccessCount ||
				(genBest.SuccessCount == GlobalBest.SuccessCount && genBest.Duration < GlobalBest.Duration) {
				GlobalBest = genBest
				fmt.Printf(">>> 🏆 NEW GLOBAL BEST: [%d/%d] %s\n", GlobalBest.SuccessCount, GlobalBest.TotalCount, GlobalBest.Strategy)
			}
		}

		if GlobalBest.SuccessCount >= TargetSuccessRate {
			fmt.Println("\n>>> 🎉 TARGET ACHIEVED!")
			break
		}

		var survivors []StrategyResult
		if GlobalBest.Strategy != "" {
			survivors = append(survivors, GlobalBest)
		}
		for i := 0; i < len(results) && len(survivors) < ElitesCount+1; i++ {
			if results[i].Strategy != GlobalBest.Strategy {
				survivors = append(survivors, results[i])
			}
		}

		if len(survivors) == 0 {
			fmt.Println("\033[33m>>> Gen failed. Injecting chaos.\033[0m")
			currentGenStrats = generateChaosPopulation(PopulationSize)
			continue
		}

		currentGenStrats = breedingProtocol(survivors, PopulationSize)
	}

	printSummary(allResults)
}

// --- Evolution Core ---

func breedingProtocol(parents []StrategyResult, populationSize int) []string {
	var nextGen []string
	seen := make(map[string]struct{})

	add := func(s string) {
		s = strings.TrimSpace(s)
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			nextGen = append(nextGen, s)
		}
	}

	// Elitism
	for _, p := range parents {
		add(p.Strategy)
	}

	rand.Seed(time.Now().UnixNano())

	// High Fidelity Mutations
	for _, p := range parents {
		cfg := ParseConfig(p.Strategy)
		for i := 0; i < 6; i++ {
			mutant := cfg
			mutant.MutateFine()
			add(mutant.String())
		}
	}

	// Cross-Over
	if len(parents) >= 2 {
		p1 := ParseConfig(parents[0].Strategy)
		p2 := ParseConfig(parents[1].Strategy)
		c1 := p1
		c1.TTL = p2.TTL
		c1.AutoTTL = p2.AutoTTL
		c1.Wssize = p2.Wssize
		add(c1.String())

		c2 := p1
		c2.Fooling = p2.Fooling
		c2.SplitSeqOvl = p2.SplitSeqOvl
		add(c2.String())
	}

	// Exploration
	for len(nextGen) < populationSize-15 {
		p := parents[rand.Intn(len(parents))]
		cfg := ParseConfig(p.Strategy)
		cfg.MutateWild()
		add(cfg.String())
	}

	// Chaos
	chaos := generateChaosPopulation(populationSize - len(nextGen))
	for _, s := range chaos {
		add(s)
	}

	return nextGen
}

// --- Config Parser/Serializer ---

func ParseConfig(s string) DPIConfig {
	c := DPIConfig{Mode: "fake", Repeats: 1, FakeTLSMod: "none"}

	// Extract Mode
	if strings.Contains(s, "split2") || strings.Contains(s, "multisplit") {
		c.Mode = "multisplit"
	} else if strings.Contains(s, "disorder2") || strings.Contains(s, "multidisorder") {
		c.Mode = "multidisorder"
	} else if strings.Contains(s, "fakedsplit") {
		c.Mode = "fakedsplit"
	} else if strings.Contains(s, "ipfrag1") {
		c.Mode = "ipfrag1"
	}

	// Extract Ints
	if match := regexp.MustCompile(`--dpi-desync-repeats=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.Repeats, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-ttl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.TTL, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-autottl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.AutoTTL, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-split-pos=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.SplitPos, _ = strconv.Atoi(match[1])
	}
	if match := regexp.MustCompile(`--dpi-desync-split-seqovl=(\d+)`).FindStringSubmatch(s); len(match) > 1 {
		c.SplitSeqOvl, _ = strconv.Atoi(match[1])
	}

	// Extract Strings
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

func (c DPIConfig) String() string {
	parts := []string{fmt.Sprintf("--dpi-desync=%s", c.Mode)}

	if c.Repeats > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-repeats=%d", c.Repeats))
	}
	if c.SplitPos > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-split-pos=%d", c.SplitPos))
	}
	if c.SplitSeqOvl > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-split-seqovl=%d", c.SplitSeqOvl))
	}
	if c.Wssize != "" {
		parts = append(parts, fmt.Sprintf("--wssize=%s", c.Wssize))
	}
	if c.Fooling != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-fooling=%s", c.Fooling))
	}
	if c.FakeTLS != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-fake-tls=%s", c.FakeTLS))
		if c.FakeTLSMod != "" {
			parts = append(parts, fmt.Sprintf("--dpi-desync-fake-tls-mod=%s", c.FakeTLSMod))
		}
	}
	if c.TTL > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-ttl=%d", c.TTL))
	} else if c.AutoTTL > 0 {
		parts = append(parts, fmt.Sprintf("--dpi-desync-autottl=%d", c.AutoTTL))
	}
	if c.Cutoff != "" {
		parts = append(parts, fmt.Sprintf("--dpi-desync-cutoff=%s", c.Cutoff))
	}
	if c.AnyProtocol {
		parts = append(parts, "--dpi-desync-any-protocol")
	}
	return strings.Join(parts, " ")
}

// Smart Mutation using Probabilities
func (c *DPIConfig) MutateFine() {
	r := rand.Float64()

	// 1. Repeats & SplitPos
	if r < 0.25 {
		if c.Repeats > 1 {
			c.Repeats += rand.Intn(3) - 1
		} else {
			c.Repeats++
		}
		if c.SplitPos > 0 {
			c.SplitPos += rand.Intn(3) - 1
			if c.SplitPos < 1 {
				c.SplitPos = 1
			}
		}
	}

	// 2. TTL
	if r >= 0.25 && r < 0.50 {
		if c.AutoTTL > 0 {
			c.AutoTTL += rand.Intn(3) - 1
			if c.AutoTTL < 0 {
				c.AutoTTL = 0
			}
		} else {
			c.TTL += rand.Intn(3) - 1
			if c.TTL < 0 {
				c.TTL = 0
			}
		}
	}

	// 3. FakeTLS & SNI
	if r >= 0.50 && r < 0.75 {
		if rand.Float64() > 0.5 && len(DiscoveredBins) > 0 {
			c.FakeTLS = DiscoveredBins[rand.Intn(len(DiscoveredBins))]
		} else {
			// Toggle Random SNI
			if c.FakeTLSMod == "none" {
				c.FakeTLSMod = "rndsni"
			} else if c.FakeTLSMod == "rndsni" {
				c.FakeTLSMod = "none"
			}
		}
	}

	// 4. Advanced Params (Wssize, Ovl)
	if r >= 0.75 {
		if c.Wssize == "" {
			c.Wssize = "1:6" // Try classic window scaling
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

func (c *DPIConfig) MutateWild() {
	r := rand.Intn(8)
	switch r {
	case 0:
		c.Repeats = rand.Intn(12) + 2
	case 1:
		modes := []string{"fake", "multidisorder", "multisplit", "fakedsplit", "ipfrag1"}
		c.Mode = modes[rand.Intn(len(modes))]
		if c.Mode == "multisplit" || c.Mode == "multidisorder" {
			c.SplitPos = rand.Intn(4) + 1
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
		c.TTL = rand.Intn(10) + 1
	case 6:
		// Enable/Disable Overlap
		if c.SplitSeqOvl == 0 {
			c.SplitSeqOvl = 1
		} else {
			c.SplitSeqOvl = 0
		}
	case 7:
		// Wssize
		if c.Wssize == "" {
			c.Wssize = "1:6"
		} else {
			c.Wssize = ""
		}
	}
}

// --- Generators ---

func generateInitialPopulation(size int) []string {
	var s []string
	base := []string{
		// Good old fake
		"--dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fooling=ts --dpi-desync-fake-tls=/app/tls_clienthello_www_google_com.bin --dpi-desync-fake-tls-mod=none",
		// Fake with Random SNI
		"--dpi-desync=fake --dpi-desync-repeats=4 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=/app/tls_clienthello_iana_org.bin --dpi-desync-fake-tls-mod=rndsni",
		// Multisplit
		"--dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-repeats=3",
		// Multisplit with overlap (Powerful!)
		"--dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=5",
		// IP Frag (Risky but good)
		"--dpi-desync=ipfrag1 --dpi-desync-repeats=3",
		// Disorder with Wssize
		"--dpi-desync=multidisorder --dpi-desync-split-pos=1 --wssize=1:6",
	}
	s = append(s, base...)
	chaos := generateChaosPopulation(size - len(s))
	s = append(s, chaos...)
	return deduplicate(s)
}

func generateChaosPopulation(n int) []string {
	var s []string
	rand.Seed(time.Now().UnixNano())

	for i := 0; i < n; i++ {
		c := DPIConfig{}
		modes := []string{"fake", "fake", "multidisorder", "multisplit", "fakedsplit"}
		c.Mode = modes[rand.Intn(len(modes))]
		c.Repeats = rand.Intn(10) + 1

		if c.Mode == "fake" || c.Mode == "fakedsplit" {
			fList := []string{"ts", "md5sig", "badsum", "datanoack"}
			c.Fooling = fList[rand.Intn(len(fList))]

			if len(DiscoveredBins) > 0 {
				c.FakeTLS = DiscoveredBins[rand.Intn(len(DiscoveredBins))]
			}

			// FakeTLS Mods
			mods := []string{"none", "rnd", "rndsni"}
			c.FakeTLSMod = mods[rand.Intn(len(mods))]
		}

		if c.Mode == "multisplit" || c.Mode == "multidisorder" {
			c.SplitPos = rand.Intn(4) + 1
			if rand.Intn(2) == 0 {
				c.SplitSeqOvl = 1
			}
		}

		// Window Size manipulation
		if rand.Intn(3) == 0 {
			c.Wssize = "1:6"
		}

		if rand.Intn(2) == 0 {
			c.TTL = rand.Intn(10) + 1
		} else {
			c.AutoTTL = rand.Intn(5) + 1
		}
		s = append(s, c.String())
	}
	return s
}

// --- Docker & Batch Utils ---

func discoverBinFiles(ctx context.Context, cli *client.Client) ([]string, error) {
	// Explicitly overriding Entrypoint to use shell, as the image has prikop as entrypoint
	resp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      ImageName,
			Entrypoint: []string{"/bin/sh", "-c", "ls -1 /app/*.bin 2>/dev/null; ls -1 /*.bin 2>/dev/null"},
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
	}()

	if _, err := cli.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return nil, err
	}

	statusCh := cli.ContainerWait(ctx, resp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-statusCh.Error:
		return nil, err
	case <-statusCh.Result:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, client.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return nil, err
	}
	defer out.Close()

	var buf bytes.Buffer
	stdcopy.StdCopy(&buf, io.Discard, out)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var files []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasSuffix(l, ".bin") {
			files = append(files, l)
		}
	}
	return deduplicate(files), nil
}

func executeBatch(ctx context.Context, cli *client.Client, strats []string, history map[string]bool, counter *int) ([]StrategyResult, int) {
	resultsCh := make(chan StrategyResult, len(strats))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, MaxWorkers)
	var results []StrategyResult

	startBatch := time.Now()
	processedInBatch := 0
	totalInBatch := 0

	var bestScoreSoFar int32 = int32(GlobalBest.SuccessCount)

	var validStrats []string
	for _, s := range strats {
		s = strings.TrimSpace(strings.ReplaceAll(s, "  ", " "))
		if !history[s] && *counter < MaxTotalAttempts {
			validStrats = append(validStrats, s)
			history[s] = true
			*counter++
		}
	}
	totalInBatch = len(validStrats)

	go func() {
		for {
			if processedInBatch >= totalInBatch {
				break
			}
			currentBest := atomic.LoadInt32(&bestScoreSoFar)
			fmt.Printf("\r\033[K>>> ⏳ Processing: %d/%d (High Score: %d)", processedInBatch, totalInBatch, currentBest)
			time.Sleep(500 * time.Millisecond)
		}
	}()

	for _, strat := range validStrats {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			workerCtx, cancel := context.WithTimeout(ctx, ContainerTimeout)
			defer cancel()

			start := time.Now()
			res, sysLogs := runContainerTest(workerCtx, cli, s)
			dur := time.Since(start)

			sr := StrategyResult{
				Strategy:     s,
				Duration:     dur,
				WorkerResult: res,
				SystemLogs:   sysLogs,
			}

			if int32(res.SuccessCount) > atomic.LoadInt32(&bestScoreSoFar) {
				for {
					current := atomic.LoadInt32(&bestScoreSoFar)
					if int32(res.SuccessCount) <= current {
						break
					}
					if atomic.CompareAndSwapInt32(&bestScoreSoFar, current, int32(res.SuccessCount)) {
						break
					}
				}
			}

			currentMax := atomic.LoadInt32(&bestScoreSoFar)
			showThreshold := int(currentMax) - 2
			if showThreshold < 1 {
				showThreshold = 1
			}

			if res.Success && res.SuccessCount >= showThreshold {
				icon := "⭐"
				color := "\033[37m"

				if res.SuccessCount >= int(currentMax) {
					icon = "🔥"
					color = "\033[32;1m"
				} else if res.SuccessCount >= TargetSuccessRate {
					icon = "🎉"
					color = "\033[33;1m"
				}

				fmt.Printf("\r\033[K%s%s [%.1fs] [%d/%d] %s\033[0m\n",
					color, icon, dur.Seconds(), res.SuccessCount, res.TotalCount, s)
			}

			resultsCh <- sr
			processedInBatch++
		}(strat)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	for res := range resultsCh {
		if res.Success {
			results = append(results, res)
		}
	}

	fmt.Printf("\r\033[K>>> Batch finished in %.2fs. Found %d working.\n", time.Since(startBatch).Seconds(), len(results))
	return results, processedInBatch
}

func deduplicate(s []string) []string {
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

func runContainerTest(ctx context.Context, cli *client.Client, strategy string) (WorkerResult, string) {
	config := &container.Config{
		Image: ImageName,
		// Passing strategy as argument instead of ENV
		Cmd: []string{"worker", strategy},
		Tty: false,
	}
	hostConfig := &container.HostConfig{
		CapAdd:      []string{"NET_ADMIN"},
		NetworkMode: "bridge",
	}

	createResp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: config, HostConfig: hostConfig})
	if err != nil {
		return WorkerResult{Error: "Docker Create: " + err.Error()}, ""
	}
	containerID := createResp.ID
	defer func() {
		_, _ = cli.ContainerRemove(context.Background(), containerID, client.ContainerRemoveOptions{Force: true})
	}()

	if _, err := cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		return WorkerResult{Error: "Docker Start: " + err.Error()}, ""
	}

	waitRes := cli.ContainerWait(ctx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-waitRes.Error:
		if err != nil {
			return WorkerResult{Error: "Docker Wait: " + err.Error()}, ""
		}
	case <-waitRes.Result:
	}

	out, _ := cli.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	defer out.Close()
	var stdoutBuf, stderrBuf bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)

	stdoutStr := strings.TrimSpace(stdoutBuf.String())
	if stdoutStr == "" {
		return WorkerResult{Error: "Empty stdout"}, stderrBuf.String()
	}

	var res WorkerResult
	if err := json.Unmarshal([]byte(stdoutStr), &res); err != nil {
		return WorkerResult{Error: "JSON Parse: " + err.Error()}, stderrBuf.String()
	}
	return res, stderrBuf.String()
}

func printSummary(results []StrategyResult) {
	if len(results) == 0 {
		fmt.Println("\n>>> NO STRATEGIES WORKED.")
		return
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].SuccessCount != results[j].SuccessCount {
			return results[i].SuccessCount > results[j].SuccessCount
		}
		return results[i].Duration < results[j].Duration
	})

	fmt.Println("\n>>> FINAL LEADERBOARD:")
	if GlobalBest.Strategy != "" {
		fmt.Printf("🏆 GLOBAL BEST: [%d/%d] %s\n", GlobalBest.SuccessCount, GlobalBest.TotalCount, GlobalBest.Strategy)
	}

	limit := 15
	if len(results) < limit {
		limit = len(results)
	}
	for i := 0; i < limit; i++ {
		s := results[i]
		fmt.Printf("%d. [%d/%d] [%.2fs] %s\n", i+1, s.SuccessCount, s.TotalCount, s.Duration.Seconds(), s.Strategy)
	}
}
