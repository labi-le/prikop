package worker

import (
	"bytes"
	"fmt"
	"os/exec"
	"prikop/internal/model"
	"prikop/internal/nfqws2"
	"syscall"
)

// SetupIptables applies rules based on target group
func SetupIptables(group string) error {
	// Flush previous rules
	_ = exec.Command("iptables", "-F", "OUTPUT").Run()

	// Direct execution implies waiting, no need to handle output/error elaborately for flush
	// Universal catch-all rules
	// TCP
	argsTCP := []string{"-I", "OUTPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "NFQUEUE", "--queue-num", model.QueueNum, "--queue-bypass"}
	if out, err := exec.Command("iptables", argsTCP...).CombinedOutput(); err != nil {
		return fmt.Errorf("tcp rule: %s", out)
	}
	// UDP
	argsUDP := []string{"-I", "OUTPUT", "-p", "udp", "-m", "multiport", "--dports", "443,50000:65535", "-j", "NFQUEUE", "--queue-num", model.QueueNum, "--queue-bypass"}
	if out, err := exec.Command("iptables", argsUDP...).CombinedOutput(); err != nil {
		return fmt.Errorf("udp rule: %s", out)
	}
	return nil
}

// Cleanup removes processes and flushes firewall
func Cleanup() {
	_ = exec.Command("pkill", "-9", "nfqws2").Run()
	_ = exec.Command("iptables", "-F", "OUTPUT").Run()
	_ = exec.Command("iptables", "-F", "INPUT").Run()
}

// StartNFQWS executes the nfqws2 binary directly.
func StartNFQWS(args []string) (*exec.Cmd, *bytes.Buffer) {
	// Prepend queue number and the lua desync library. nfqws2 has no built-in
	// desync engine: strategies are lua functions loaded via --lua-init.
	finalArgs := append([]string{
		"--qnum=" + model.QueueNum,
		"--lua-init=@/app/lua/zapret-lib.lua",
		"--lua-init=@/app/lua/zapret-antidpi.lua",
		// Named blobs the genome may reference (google ClientHello / QUIC Initial).
		"--blob=" + nfqws2.BlobGoogleTLS + ":@/app/fake/tls_clienthello_www_google_com.bin",
		"--blob=" + nfqws2.BlobGoogleQUIC + ":@/app/fake/quic_initial_www_google_com.bin",
	}, args...)

	cmd := exec.Command("/usr/bin/nfqws2", finalArgs...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// Setpgid creates a new process group, useful for killing the whole tree if needed
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, nil
	}
	return cmd, &out
}
