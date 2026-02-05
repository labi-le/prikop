package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const (
	TargetURL = "https://rr1---sn-gvnuxaxjvh-jx3z.googlevideo.com"
	QueueNum  = "200"
	ImageName = "prikop:latest"
)

type WorkerResult struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Error   string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		runWorkerMode()
	} else {
		runOrchestratorMode()
	}
}

func runWorkerMode() {
	strategy := os.Getenv("ZSCAN_STRATEGY")
	if strategy == "" {
		fatalJSON("No strategy provided")
	}

	// 1. iptables
	cmds := [][]string{
		{"iptables", "-t", "mangle", "-F"},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", QueueNum},
		{"iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", QueueNum},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fatalJSON(fmt.Sprintf("iptables error: %v | out: %s", err, string(out)))
		}
	}

	// 2. nfqws
	nfqwsArgs := strings.Fields(fmt.Sprintf("--qnum=%s %s", QueueNum, strategy))
	cmd := exec.Command("/usr/bin/nfqws", nfqwsArgs...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		fatalJSON(fmt.Sprintf("nfqws start failed: %v", err))
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	time.Sleep(500 * time.Millisecond)

	// 3. HTTP Client
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: -1,
			}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}

	resp, err := httpClient.Get(TargetURL)
	if err != nil {
		printJSON(WorkerResult{Success: false, Code: 0, Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	success := resp.StatusCode >= 200 && resp.StatusCode < 400
	printJSON(WorkerResult{Success: success, Code: resp.StatusCode})
}

func printJSON(res WorkerResult) {
	json.NewEncoder(os.Stdout).Encode(res)
}

func fatalJSON(msg string) {
	json.NewEncoder(os.Stdout).Encode(WorkerResult{Success: false, Error: msg})
}

func runOrchestratorMode() {
	ctx := context.Background()

	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}
	defer cli.Close()

	strategies := []string{
		"--dpi-desync=fake",
		"--dpi-desync=split2",
		"--dpi-desync=disorder2",
		"--dpi-desync=fake,split2",
		"--dpi-desync=fake --dpi-desync-ttl=3",
		"--dpi-desync=split2 --dpi-desync-split-pos=1",
	}

	fmt.Printf(">>> Starting Prikop Moby Orchestrator [%d strategies]\n", len(strategies))

	resultsCh := make(chan string, len(strategies))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)

	for _, strat := range strategies {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := runContainerTest(ctx, cli, s)

			if res.Success {
				msg := fmt.Sprintf("\033[32m[OK]\033[0m %-50s | Code: %d", s, res.Code)
				resultsCh <- msg
				fmt.Println(msg)
			} else {
				fmt.Printf("\033[31m[FAIL]\033[0m %-50s | Err: %s\n", s, res.Error)
			}
		}(strat)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	fmt.Println("\n>>> Waiting for workers...")
	for range resultsCh {
	}
	fmt.Println("Done.")
}

func runContainerTest(ctx context.Context, cli *client.Client, strategy string) WorkerResult {
	config := &container.Config{
		Image: ImageName,
		// ЯВНО передаем команду worker
		Cmd: []string{"worker"},
		Env: []string{
			"ZSCAN_STRATEGY=" + strategy,
		},
		Tty: false,
	}

	hostConfig := &container.HostConfig{
		CapAdd:      []string{"NET_ADMIN"},
		NetworkMode: "bridge",
	}

	createResp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     config,
		HostConfig: hostConfig,
	})
	if err != nil {
		return WorkerResult{Error: "Create: " + err.Error()}
	}

	defer func() {
		_, _ = cli.ContainerRemove(ctx, createResp.ID, client.ContainerRemoveOptions{Force: true})
	}()

	if _, err := cli.ContainerStart(ctx, createResp.ID, client.ContainerStartOptions{}); err != nil {
		return WorkerResult{Error: "Start: " + err.Error()}
	}

	waitRes := cli.ContainerWait(ctx, createResp.ID, client.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})

	select {
	case err := <-waitRes.Error:
		if err != nil {
			return WorkerResult{Error: "Wait error: " + err.Error()}
		}
	case <-waitRes.Result:
	}

	logsReadCloser, err := cli.ContainerLogs(ctx, createResp.ID, client.ContainerLogsOptions{
		ShowStdout: true,
	})
	if err != nil {
		return WorkerResult{Error: "Logs: " + err.Error()}
	}
	defer logsReadCloser.Close()

	buf := new(strings.Builder)
	if _, err := stdcopy.StdCopy(buf, io.Discard, logsReadCloser); err != nil {
		return WorkerResult{Error: "StdCopy: " + err.Error()}
	}

	jsonStr := strings.TrimSpace(buf.String())
	if jsonStr == "" {
		return WorkerResult{Error: "Empty output"}
	}

	var res WorkerResult
	if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
		return WorkerResult{Error: "JSON Parse: " + err.Error() + " | Raw: " + jsonStr}
	}

	return res
}
