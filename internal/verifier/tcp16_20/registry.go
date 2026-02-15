package tcp16_20

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"prikop/internal/verifier/types"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

func InitializeProviders(shouldFetchCIDRs bool, only string, log zerolog.Logger) ([]types.ProviderDefinition, error) {
	var source []types.ProviderDefinition
	if only != "" {
		for _, d := range definitions {
			if d.Name == only {
				source = append(source, d)
				break
			}
		}
	} else {
		source = definitions
	}

	result := make([]types.ProviderDefinition, len(source))
	copy(result, source)

	if err := os.MkdirAll(TargetsDir, 0777); err != nil {
		log.Warn().Err(err).Msg("Failed to create targets directory")
	}

	for i := range result {
		for j := range result[i].Targets {
			if result[i].Targets[j].Threshold == 0 {
				result[i].Targets[j].Threshold = 1024
			}
		}
	}

	if shouldFetchCIDRs {
		fetchCIDRs(result, log)
	}

	return result, nil
}

func fetchCIDRs(providers []types.ProviderDefinition, log zerolog.Logger) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for i := range providers {
		if providers[i].CIDRSource == "" {
			continue
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			def := &providers[idx]
			provLog := log.With().Str("provider", def.Name).Str("source", def.CIDRSource).Logger()
			provLog.Info().Msg("Fetching CIDRs")

			cidrs, err := downloadCIDRs(def.CIDRSource)
			if err != nil {
				provLog.Error().Err(err).Msg("Error fetching CIDRs")
				return
			}

			if len(cidrs) > 0 {
				filePath := filepath.Join(TargetsDir, def.Name+"-cidr.txt")
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

func downloadCIDRs(rawURL string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseCIDRs(body)
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
