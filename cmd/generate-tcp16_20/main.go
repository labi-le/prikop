// Command generate-tcp16_20 fetches the DPI checker suite from
// https://github.com/hyperion-cs/dpi-checkers and generates a single Go file
// tcp16_20_generated.go inside internal/verifier/tcp16_20.
//
// Usage:
//
//	go run ./cmd/generate-tcp16_20
//	go run ./cmd/generate-tcp16_20 -url <url>
//	go run ./cmd/generate-tcp16_20 -out <path>
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
	defaultSuiteURL   = "https://raw.githubusercontent.com/hyperion-cs/dpi-checkers/refs/heads/main/ru/tcp-16-20/suite.v2.json"
	defaultOutputFile = "internal/verifier/tcp16_20/suite_v1_generated.go"
)

// SuiteEntryV2 represents the v2 suite schema
type SuiteEntryV2 struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Host     string `json:"host"`
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

var cidrSources = map[string]string{
	"akamai":       "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/akamai/akamai_plain_ipv4.txt",
	"aws":          "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/aws/aws_plain_ipv4.txt",
	"cdn77":        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cdn77/cdn77_plain_ipv4.txt",
	"cloudflare":   "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/cloudflare/cloudflare_plain_ipv4.txt",
	"contabo":      "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/contabo/contabo_plain_ipv4.txt",
	"digitalocean": "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/digitalocean/digitalocean_plain_ipv4.txt",
	"fastly":       "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/fastly/fastly_plain_ipv4.txt",
	"gcore":        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/gcore/gcore_plain_ipv4.txt",
	"googlecloud":  "https://www.gstatic.com/ipranges/cloud.json",
	"hetzner":      "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/hetzner/hetzner_plain_ipv4.txt",
	"melbicom":     "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/melbicom/melbicom_plain_ipv4.txt",
	"oracle":       "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/oracle/oracle_plain_ipv4.txt",
	"ovh":          "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/ovh/ovh_plain_ipv4.txt",
	"scaleway":     "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/scaleway/scaleway_plain_ipv4.txt",
	"vultr":        "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/refs/heads/main/vultr/vultr_ips_merged_v4.txt",
}

func main() {
	var suiteURL string
	var outputFile string
	var gens int

	flag.StringVar(&suiteURL, "url", defaultSuiteURL, "suite.v2.json URL")
	flag.StringVar(&outputFile, "out", defaultOutputFile, "output file path")
	flag.IntVar(&gens, "gens", 3, "number of generations")
	flag.Parse()

	entries, err := fetchSuiteV2(suiteURL)
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
		_ = os.WriteFile(outputFile+".broken", buf.Bytes(), 0644)
		fatal("gofmt: %v (unformatted source saved to %s.broken)", err, outputFile)
	}

	if err := os.WriteFile(outputFile, formatted, 0644); err != nil {
		fatal("writing file: %v", err)
	}

	fmt.Printf("Generated %s (%d providers, %d targets)\n",
		outputFile, len(data.Providers), len(entries))
}

const defaultThreshold = 64 * 1024 // 64KB as per dpi-checkers algorithm

func buildTemplateData(entries []SuiteEntryV2, gens int) (templateData, error) {
	// Group by provider slug
	grouped := make(map[string][]SuiteEntryV2)
	for _, e := range entries {
		slug := strings.ToLower(strings.ReplaceAll(e.Provider, " ", "-"))
		grouped[slug] = append(grouped[slug], e)
	}

	names := sortedKeysV2(grouped)
	var provs []templateProvider

	for _, slug := range names {
		entryList := grouped[slug]
		var targets []templateTarget

		for _, e := range entryList {
			// Construct full URL from host
			url := "https://" + e.Host + "/"
			targets = append(targets, templateTarget{
				ID:        e.ID,
				URL:       url,
				Threshold: defaultThreshold,
			})
		}

		cidrFile := ""
		if cidrURL, ok := cidrSources[slug]; ok {
			var err error
			cidrFile, err = downloadAndSaveCIDRs(slug, cidrURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: downloading CIDRs for %s: %v (skipping)\n", slug, err)
				cidrFile = ""
			}
		}

		provs = append(provs, templateProvider{
			Name:     slug,
			Slug:     slug,
			CIDR:     cidrSources[slug],
			CIDRFile: cidrFile,
			Targets:  targets,
			Gens:     gens,
		})
	}

	return templateData{Providers: provs}, nil
}

func sortedKeysV2(m map[string][]SuiteEntryV2) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fetchSuiteV2(url string) ([]SuiteEntryV2, error) {
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

	var entries []SuiteEntryV2
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate-tcp16_20: "+format+"\n", args...)
	os.Exit(1)
}

// downloadAndSaveCIDRs downloads CIDRs from URL and saves to targets/<slug>-cidr.txt
// Returns relative path from project root (e.g. "targets/aws-cidr.txt")
func downloadAndSaveCIDRs(slug, url string) (string, error) {
	// Get the directory where the generated file will be placed
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	// Navigate from internal/verifier/tcp16_20 to project root
	projectRoot := filepath.Join(wd, "..", "..", "..")
	targetsDir := filepath.Join(projectRoot, "targets")

	if err := os.MkdirAll(targetsDir, 0755); err != nil {
		return "", fmt.Errorf("creating targets directory: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	cidrs, err := parseCIDRs(body)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(targetsDir, slug+"-cidr.txt")
	f, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, cidr := range cidrs {
		if _, err := f.WriteString(cidr + "\n"); err != nil {
			return "", err
		}
	}

	fmt.Printf("Downloaded %d CIDRs for %s -> %s\n", len(cidrs), slug, filePath)
	return "targets/" + slug + "-cidr.txt", nil
}

func parseCIDRs(body []byte) ([]string, error) {
	type fastlyResp struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	type googlePrefix struct {
		IPv4Prefix string `json:"ipv4Prefix"`
	}
	type googleResp struct {
		Prefixes []googlePrefix `json:"prefixes"`
	}

	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var gResp googleResp
		if err := json.Unmarshal(body, &gResp); err == nil && len(gResp.Prefixes) > 0 {
			var result []string
			for _, p := range gResp.Prefixes {
				if p.IPv4Prefix != "" {
					result = append(result, p.IPv4Prefix)
				}
			}
			return result, nil
		}

		var fResp fastlyResp
		if err := json.Unmarshal(body, &fResp); err == nil && len(fResp.Addresses) > 0 {
			return fResp.Addresses, nil
		}
	}

	lines := strings.Split(string(body), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ".") {
			result = append(result, line)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid IPv4 CIDRs found")
	}

	return result, nil
}
