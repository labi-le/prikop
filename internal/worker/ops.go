package worker

import (
	"bytes"
	"fmt"
	"os/exec"
	"prikop/internal/model"
	"syscall"
)

// SetupIptables applies rules based on target group
func SetupIptables(group string) error {
	// Flush previous rules
	exec.Command("iptables", "-F", "OUTPUT").Run()

	// Logic preserved: Universal catch-all rules
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
	exec.Command("pkill", "-9", "nfqws").Run()
	exec.Command("iptables", "-F", "OUTPUT").Run()
	exec.Command("iptables", "-F", "INPUT").Run()
}

// StartNFQWS executes the nfqws binary
func StartNFQWS(args string) (*exec.Cmd, *bytes.Buffer) {
	fullCmd := fmt.Sprintf("/usr/bin/nfqws --qnum=%s %s", model.QueueNum, args)
	cmd := exec.Command("sh", "-c", fullCmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, nil
	}
	return cmd, &out
}

// KillCmd force kills the process
func KillCmd(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
	}
}
