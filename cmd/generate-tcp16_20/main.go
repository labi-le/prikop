// Command generate-tcp16_20 fetches the DPI-detector suite (IP endpoints per
// hosting provider) and generates suite_v1_generated.go plus a per-provider
// ipset file (targets/<slug>-cidr.txt) containing the exact test IPs as /32.
//
// Usage:
//
//	go run ./cmd/generate-tcp16_20
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

// targetURL builds the check URL from an IP and port.
func targetURL(ip string, port int) string {
	switch port {
	case 0, 443:
		return "https://" + ip + "/"
	case 80:
		return "http://" + ip + "/"
	default:
		return fmt.Sprintf("https://%s:%d/", ip, port)
	}
}

func buildTemplateData(entries []SuiteEntry, gens int) (templateData, error) {
	grouped := make(map[string][]SuiteEntry)
	for _, e := range entries {
		if e.IP == "" {
			continue
		}
		slug := baseSlug(e.Provider)
		grouped[slug] = append(grouped[slug], e)
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
		seen := make(map[string]struct{})
		var ips []string
		for _, e := range list {
			targets = append(targets, templateTarget{
				ID:        e.ID,
				URL:       targetURL(e.IP, e.Port),
				Threshold: defaultThreshold,
			})
			if _, ok := seen[e.IP]; !ok {
				seen[e.IP] = struct{}{}
				ips = append(ips, e.IP)
			}
		}

		cidrFile, err := writeIPSet(slug, ips)
		if err != nil {
			return templateData{}, fmt.Errorf("writing ipset for %s: %w", slug, err)
		}

		provs = append(provs, templateProvider{
			Name:     slug,
			Slug:     slug,
			CIDR:     "", // ipset is built from the suite's exact IPs
			CIDRFile: cidrFile,
			Targets:  targets,
			Gens:     gens,
		})
	}

	return templateData{Providers: provs}, nil
}

// writeIPSet writes the provider's test IPs as /32 CIDRs to
// targets/<slug>-cidr.txt and returns the project-relative path.
func writeIPSet(slug string, ips []string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// go:generate runs in internal/verifier/tcp16_20; project root is 3 up.
	targetsDir := filepath.Join(wd, "..", "..", "..", "targets")
	if err := os.MkdirAll(targetsDir, 0o755); err != nil {
		return "", err
	}

	sort.Strings(ips)
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(ip)
		b.WriteString("/32\n")
	}

	path := filepath.Join(targetsDir, slug+"-cidr.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	fmt.Printf("Wrote %d IPs for %s -> %s\n", len(ips), slug, path)
	return "targets/" + slug + "-cidr.txt", nil
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
