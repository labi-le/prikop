package verifier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const TargetsDir = "/app/targets"

var (
	providerRepo = make(map[string]ProviderDefinition)
	repoMu       sync.RWMutex
)

func InitializeProviders(shouldFetchCIDRs bool, log zerolog.Logger) ([]ProviderDefinition, error) {
	var definitions = make([]ProviderDefinition, len(StaticProviders))
	copy(definitions, StaticProviders)

	if err := os.MkdirAll(TargetsDir, 0777); err != nil {
		log.Warn().Err(err).Msg("Failed to create targets directory")
	}

	for i := range definitions {
		for j := range definitions[i].Targets {
			if definitions[i].Targets[j].Threshold == 0 {
				definitions[i].Targets[j].Threshold = 1024
			}
		}
	}

	if shouldFetchCIDRs {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 5)
		client := &http.Client{Timeout: 30 * time.Second}

		for i := range definitions {
			if definitions[i].CIDRSource == "" {
				continue
			}

			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				def := &definitions[idx]
				src := def.CIDRSource
				provLog := log.With().Str("provider", def.Name).Str("source", src).Logger()
				provLog.Info().Msg("Fetching CIDRs")

				cidrs, err := downloadCIDRs(client, src)
				if err != nil {
					provLog.Error().Err(err).Msg("Error fetching CIDRs")
					return
				}

				if len(cidrs) > 0 {
					fileName := fmt.Sprintf("%s-cidr.txt", def.Name)
					filePath := filepath.Join(TargetsDir, fileName)

					if err := saveCIDRsToFile(filePath, cidrs); err != nil {
						provLog.Error().Err(err).Msg("Error saving CIDRs to file")
					} else {
						def.CIDRFile = filePath
						provLog.Info().Int("count", len(cidrs)).Str("path", filePath).Msg("Saved CIDRs")
					}
				}
			}(i)
		}

		wg.Wait()
	}

	repoMu.Lock()
	defer repoMu.Unlock()

	providerRepo = make(map[string]ProviderDefinition)
	for _, def := range definitions {
		providerRepo[def.Name] = def
	}

	return definitions, nil
}

func saveCIDRsToFile(path string, cidrs []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cidr := range cidrs {
		if _, err := f.WriteString(cidr + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func downloadCIDRs(client *http.Client, url string) ([]string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

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

func GetProvider(name string) (ProviderDefinition, bool) {
	repoMu.RLock()
	defer repoMu.RUnlock()
	p, ok := providerRepo[name]
	return p, ok
}
