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
	"sort"
	"strings"
	"text/template"
	"time"
)

//go:embed tcp16_20.go.tmpl
var tmplFS embed.FS

const (
	defaultSuiteURL   = "https://raw.githubusercontent.com/hyperion-cs/dpi-checkers/refs/heads/main/ru/tcp-16-20/suite.json"
	defaultOutputFile = "internal/verifier/tcp16_20_generated/tcp16_20_generated.go"
)

type SuiteEntry struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	Country        string `json:"country"`
	ThresholdBytes int    `json:"thresholdBytes"`
	Times          int    `json:"times"`
	URL            string `json:"url"`
}

type templateTarget struct {
	URL       string
	Threshold int
}

type templateProvider struct {
	Name    string
	Slug    string
	CIDR    string
	Targets []templateTarget
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
	"vultr":        "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/vultr/vultr_plain_ipv4.txt",
}

func main() {
	suiteURL := flag.String("url", defaultSuiteURL, "suite.json URL")
	outputFile := flag.String("out", defaultOutputFile, "output file path")
	flag.Parse()

	entries, err := fetchSuite(*suiteURL)
	if err != nil {
		fatal("fetching suite: %v", err)
	}

	grouped := groupByProvider(entries)
	data := buildTemplateData(grouped)

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
		_ = os.WriteFile(*outputFile+".broken", buf.Bytes(), 0644)
		fatal("gofmt: %v (unformatted source saved to %s.broken)", err, *outputFile)
	}

	if err := os.WriteFile(*outputFile, formatted, 0644); err != nil {
		fatal("writing file: %v", err)
	}

	fmt.Printf("Generated %s (%d providers, %d targets)\n",
		*outputFile, len(data.Providers), len(entries))
}

func buildTemplateData(grouped map[string][]SuiteEntry) templateData {
	names := sortedKeys(grouped)
	var provs []templateProvider
	for _, name := range names {
		slug := strings.ToLower(strings.ReplaceAll(name, " ", ""))
		var targets []templateTarget
		for _, e := range grouped[name] {
			targets = append(targets, templateTarget{URL: e.URL, Threshold: e.ThresholdBytes})
		}
		provs = append(provs, templateProvider{
			Name:    name,
			Slug:    slug,
			CIDR:    cidrSources[slug],
			Targets: targets,
		})
	}
	return templateData{Providers: provs}
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

func groupByProvider(entries []SuiteEntry) map[string][]SuiteEntry {
	grouped := make(map[string][]SuiteEntry)
	for _, e := range entries {
		grouped[e.Provider] = append(grouped[e.Provider], e)
	}
	return grouped
}

func sortedKeys(m map[string][]SuiteEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate-tcp16_20: "+format+"\n", args...)
	os.Exit(1)
}
