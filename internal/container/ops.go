package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiscoverBinFiles scans the directory for .bin files natively.
func DiscoverBinFiles(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", path, err)
	}

	var bins []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".bin") {
			bins = append(bins, filepath.Join(path, name))
		}
	}

	if len(bins) == 0 {
		return nil, fmt.Errorf("no .bin files found in %s", path)
	}

	return bins, nil
}
