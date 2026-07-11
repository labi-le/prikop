package checker

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return n
}

func TestValidateIP(t *testing.T) {
	// IP-literal URLs make net.LookupIP resolve without a DNS query, keeping
	// this test deterministic and offline.
	nets := []*net.IPNet{mustCIDR(t, "8.8.8.0/24")}

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"in range", "https://8.8.8.8", false},
		{"in range with port", "https://8.8.8.8:443", false},
		{"out of range", "https://1.1.1.1", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIP(tc.url, nets)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateIP(%q) err = %v, wantErr = %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestLoadCIDRs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cidr.txt")
	content := "# a comment\n8.8.8.0/24\n\n  1.1.1.0/24  \nnot-a-cidr\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	nets, err := LoadCIDRs(path)
	if err != nil {
		t.Fatalf("LoadCIDRs: %v", err)
	}
	// comment, blank line and garbage are skipped -> 2 valid networks.
	if len(nets) != 2 {
		t.Fatalf("len(nets) = %d, want 2", len(nets))
	}

	if _, err := LoadCIDRs(filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatalf("LoadCIDRs(missing) = nil error, want error")
	}
}
