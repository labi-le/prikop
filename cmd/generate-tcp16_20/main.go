// Command generate-tcp16_20 fetches the DPI-detector suite (IP endpoints per
// hosting provider) and generates suite_v1_generated.go plus a per-provider
// ipset file (targets/<slug>-cidr.txt).
//
// The ipset is the union of every provider ASN's announced IPv4 prefixes
// (via RIPEstat) and the suite's exact test IPs as host routes. The prefixes
// give deployment-ready coverage of the whole provider range; the host routes
// guarantee the test IPs pass startup CIDR validation even when their ASN
// attribution differs from RIPE's announced set. ASN lookups degrade
// gracefully: on failure a provider falls back to host routes only.
//
// Usage (canonical — regenerates the suite and ipset files):
//
//	go generate ./internal/verifier/tcp16_20/
//
// It locates the module root via go.mod, so it also works standalone:
//
//	go run ./cmd/generate-tcp16_20 -url <url> -out <path> -gens <n>
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"
)

//go:embed tcp16_20.go.tmpl
var tmplFS embed.FS

const (
	defaultSuiteURL   = "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/refs/heads/main/tcp16.json"
	defaultOutputFile = "internal/verifier/tcp16_20/suite_v1_generated.go"
	defaultThreshold  = 64 * 1024 // 64KB per the dpi-checkers algorithm
	ripeStatURL       = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"
)

// SuiteEntry is one endpoint in the DPI-detector suite.
type SuiteEntry struct {
	ID       string `json:"id"`
	ASN      string `json:"asn"`
	Provider string `json:"provider"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	SNI      string `json:"sni"`
}

type templateTarget struct {
	ID        string
	URL       string
	Threshold int
	SNI       string
}

type templateProvider struct {
	Name     string
	Slug     string
	CIDR     string
	CIDRFile string
	Targets  []templateTarget
	Gens     int
}

type templateData struct {
	Providers []templateProvider
}

func main() {
	var suiteURL, outputFile string
	var gens int
	flag.StringVar(&suiteURL, "url", defaultSuiteURL, "suite json URL")
	flag.StringVar(&outputFile, "out", defaultOutputFile, "output file path")
	flag.IntVar(&gens, "gens", 3, "number of generations")
	flag.Parse()

	entries, err := fetchSuite(suiteURL)
	if err != nil {
		fatal("fetching suite: %v", err)
	}

	data, err := buildTemplateData(entries, gens)
	if err != nil {
		fatal("building template data: %v", err)
	}

	tmpl, err := template.ParseFS(tmplFS, "tcp16_20.go.tmpl")
	if err != nil {
		fatal("parsing template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		fatal("executing template: %v", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		_ = os.WriteFile(outputFile+".broken", buf.Bytes(), 0o644)
		fatal("gofmt: %v (unformatted source saved to %s.broken)", err, outputFile)
	}

	if err := os.WriteFile(outputFile, formatted, 0o644); err != nil {
		fatal("writing file: %v", err)
	}

	fmt.Printf("Generated %s (%d providers, %d endpoints)\n", outputFile, len(data.Providers), len(entries))
}

// baseSlug normalizes a granular provider name ("Hetzner Cloud 2",
// "Akamai 1 HTTP", "CDN77 #1", "Google Cloud") to a stable base slug used for
// grouping and ipset file names.
func baseSlug(provider string) string {
	fields := strings.Fields(provider)
	if len(fields) == 0 {
		return "unknown"
	}
	first := strings.ToLower(fields[0])
	// "Google Cloud" is the only two-word base name in the suite.
	if first == "google" && len(fields) > 1 && strings.ToLower(fields[1]) == "cloud" {
		return "googlecloud"
	}
	return first
}

// asNum extracts the leading numeric AS number from a raw suite value that may
// carry decoration (e.g. "24940☆" -> "24940").
func asNum(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hostCIDR renders an IP as a host route (/32 for IPv4, /128 for IPv6).
func hostCIDR(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

// targetURL builds the check URL from an IP and port (IPv6 bracketed).
func targetURL(ip string, port int) string {
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	switch port {
	case 0, 443:
		return "https://" + host + "/"
	case 80:
		return "http://" + host + "/"
	default:
		return fmt.Sprintf("https://%s:%d/", host, port)
	}
}

func buildTemplateData(entries []SuiteEntry, gens int) (templateData, error) {
	grouped := make(map[string][]SuiteEntry)
	for _, e := range entries {
		if e.IP == "" {
			continue
		}
		grouped[baseSlug(e.Provider)] = append(grouped[baseSlug(e.Provider)], e)
	}

	slugs := make([]string, 0, len(grouped))
	for s := range grouped {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)

	var provs []templateProvider
	for _, slug := range slugs {
		list := grouped[slug]

		var targets []templateTarget
		seenTarget := make(map[string]struct{})
		cidrs := make(map[string]struct{})
		asns := make(map[string]struct{})

		for _, e := range list {
			url := targetURL(e.IP, e.Port)
			if _, ok := seenTarget[url]; !ok {
				seenTarget[url] = struct{}{}
				targets = append(targets, templateTarget{
					ID:        e.ID,
					URL:       url,
					Threshold: defaultThreshold,
					SNI:       e.SNI,
				})
			}
			cidrs[hostCIDR(e.IP)] = struct{}{} // host route guarantees CIDR validation passes
			if n := asNum(e.ASN); n != "" {
				asns[n] = struct{}{}
			}
		}

		for asn := range asns {
			prefixes, err := asnPrefixes(asn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: AS%s prefixes for %s: %v (host routes only)\n", asn, slug, err)
				continue
			}
			for _, p := range prefixes {
				cidrs[p] = struct{}{}
			}
		}

		cidrFile, err := writeCIDRs(slug, cidrs)
		if err != nil {
			return templateData{}, fmt.Errorf("writing ipset for %s: %w", slug, err)
		}

		provs = append(provs, templateProvider{
			Name:     slug,
			Slug:     slug,
			CIDR:     "AS " + strings.Join(sortedKeys(asns), ","),
			CIDRFile: cidrFile,
			Targets:  targets,
			Gens:     gens,
		})
	}

	return templateData{Providers: provs}, nil
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var asnCache = make(map[string][]string)

// asnPrefixes returns the ASN's announced IPv4 prefixes (RIPEstat), memoized.
func asnPrefixes(asn string) ([]string, error) {
	if v, ok := asnCache[asn]; ok {
		return v, nil
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(ripeStatURL + asn)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var r struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	var out []string
	for _, p := range r.Data.Prefixes {
		if strings.Contains(p.Prefix, ".") { // IPv4 only; prikop drives the IPv4 path
			out = append(out, p.Prefix)
		}
	}
	asnCache[asn] = out
	return out, nil
}

// writeCIDRs writes the sorted CIDR set to targets/<slug>-cidr.txt (under the
// module root) and returns the project-relative path.
func writeCIDRs(slug string, cidrs map[string]struct{}) (string, error) {
	root, err := projectRoot()
	if err != nil {
		return "", err
	}
	targetsDir := filepath.Join(root, "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		return "", err
	}

	list := sortedKeys(cidrs)
	var b strings.Builder
	for _, c := range list {
		b.WriteString(c)
		b.WriteByte('\n')
	}

	path := filepath.Join(targetsDir, slug+"-cidr.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	fmt.Printf("Wrote %d CIDRs for %s -> %s\n", len(list), slug, path)
	return "targets/" + slug + "-cidr.txt", nil
}

// projectRoot walks up from the current directory to the module root (the
// directory containing go.mod), so ipset output lands correctly whether the
// tool runs via `go generate` (cwd = the source package) or `go run` from any
// directory.
func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above working directory")
		}
		dir = parent
	}
}

func fetchSuite(url string) ([]SuiteEntry, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []SuiteEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate-tcp16_20: "+format+"\n", args...)
	os.Exit(1)
}
