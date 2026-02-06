package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"prikop/internal/model"
	"prikop/internal/verifier"
	"strings"
	"time"
)

func RunWorkerMode(strategyArgs string, targetGroup string) {
	setupIptables(targetGroup)

	cmd, stderr := startNFQWS(strategyArgs)
	defer killCmd(cmd)

	v := verifier.NewVerifier(targetGroup)
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), model.CheckTimeout)
	defer cancel()

	checkRes := v.Run(ctx)

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		fatalJSON("NFQWS crashed: " + stderr.String())
	}

	res := model.WorkerResult{
		Success:      checkRes.Success,
		SuccessCount: checkRes.SuccessCount,
		TotalCount:   checkRes.TotalCount,
		Passed:       checkRes.PassedUrls,
		Failed:       checkRes.FailedUrls,
		Code:         200,
	}
	printJSON(res)
}

func setupIptables(group string) {
	cmds := [][]string{
		{"iptables", "-t", "mangle", "-F"},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", model.QueueNum},
	}

	if strings.Contains(group, "discord_udp") {
		cmds = append(cmds, []string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "50000:65535", "-j", "NFQUEUE", "--queue-num", model.QueueNum})
	} else if strings.Contains(group, "discord_l7") {
		// Specific ports for L7 test
		cmds = append(cmds, []string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "19294:19344", "-j", "NFQUEUE", "--queue-num", model.QueueNum})
		cmds = append(cmds, []string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "50000:50100", "-j", "NFQUEUE", "--queue-num", model.QueueNum})
	} else if strings.Contains(group, "discord") {
		// Fallback for generic discord group if logic matches
		cmds = append(cmds, []string{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "50000:65535", "-j", "NFQUEUE", "--queue-num", model.QueueNum})
	}

	for _, args := range cmds {
		_ = exec.Command(args[0], args[1:]...).Run()
	}
}

func startNFQWS(args string) (*exec.Cmd, *bytes.Buffer) {
	fullArgs := strings.Fields(fmt.Sprintf("--qnum=%s %s", model.QueueNum, args))
	cmd := exec.Command("nfqws", fullArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		fatalJSON(fmt.Sprintf("Failed to start nfqws: %v", err))
	}
	return cmd, &stderr
}

func killCmd(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func fatalJSON(err string) {
	printJSON(model.WorkerResult{Success: false, Error: err})
	os.Exit(1)
}
