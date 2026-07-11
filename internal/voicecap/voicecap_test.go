package voicecap

import "testing"

// TestClassifyBidirectional: a real discord.media flow (bidirectional) must win
// over BitTorrent noise squatting the 50000 range, and be flagged bidirectional.
func TestClassifyBidirectional(t *testing.T) {
	lines := []string{
		"1.0 IP 192.168.1.5.52400 > 104.29.153.182.19297: UDP, length 47",
		"1.0 IP 192.168.1.5.52400 > 104.29.153.182.19297: UDP, length 47",
		"1.0 IP 104.29.153.182.19297 > 192.168.1.5.52400: UDP, length 8",
		"1.0 IP 104.29.153.182.19297 > 192.168.1.5.52400: UDP, length 74",
		"1.0 IP 192.168.1.5.6881 > 113.195.147.241.50000: UDP, length 80", // BitTorrent noise
		"1.0 IP6 fe80::1.5353 > ff02::fb.5353: UDP, length 10",            // non-IPv4, skipped
		"garbage line",
	}
	res := Classify(lines)
	if len(res.Flows) != 2 {
		t.Fatalf("flows = %d, want 2", len(res.Flows))
	}
	top := res.Flows[0]
	if top.Server != "104.29.153.182.19297" {
		t.Fatalf("top server = %q, want 104.29.153.182.19297", top.Server)
	}
	if top.OutPkts != 2 || top.InPkts != 2 {
		t.Fatalf("top out/in = %d/%d, want 2/2", top.OutPkts, top.InPkts)
	}
	if top.OutBytes != 94 || top.InBytes != 82 {
		t.Fatalf("top out/in bytes = %d/%d, want 94/82", top.OutBytes, top.InBytes)
	}
	if !res.Bidirectional {
		t.Fatal("want Bidirectional=true (top flow has inbound)")
	}
}

// TestClassifyBlocked: outbound-only packets => server never answered => blocked.
func TestClassifyBlocked(t *testing.T) {
	lines := []string{
		"1.0 IP 192.168.1.5.52400 > 35.214.1.2.50005: UDP, length 47",
		"1.0 IP 192.168.1.5.52400 > 35.214.1.2.50005: UDP, length 47",
		"1.0 IP 192.168.1.5.52400 > 35.214.1.2.50005: UDP, length 47",
	}
	res := Classify(lines)
	if len(res.Flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(res.Flows))
	}
	if res.Flows[0].InPkts != 0 || res.Flows[0].OutPkts != 3 {
		t.Fatalf("out/in = %d/%d, want 3/0", res.Flows[0].OutPkts, res.Flows[0].InPkts)
	}
	if res.Bidirectional {
		t.Fatal("want Bidirectional=false (no inbound => blocked)")
	}
}

// TestClassifyEmpty: no voice packets => no flows, not bidirectional.
func TestClassifyEmpty(t *testing.T) {
	res := Classify([]string{"1.0 IP 1.2.3.4.443 > 5.6.7.8.443: UDP, length 20", ""})
	if len(res.Flows) != 0 || res.Bidirectional {
		t.Fatalf("want empty non-bidirectional, got %+v", res)
	}
}
