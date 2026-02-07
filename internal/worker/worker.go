package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"prikop/internal/model"
	"prikop/internal/verifier"
	"time"
)

// RunWorkerServer starts the worker in listening mode
func RunWorkerServer(socketPath string) {
	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fatalJSON(fmt.Sprintf("listen error: %v", err))
	}
	// Make socket accessible to everyone (orchestrator needs to read/write)
	if err := os.Chmod(socketPath, 0777); err != nil {
		fmt.Fprintf(os.Stderr, "chmod warning: %v\n", err)
	}
	defer listener.Close()

	fmt.Printf("Worker listening on %s\n", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}

		// Blocks to process one request at a time (container has only 1 worker anyway)
		handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	var req model.WorkerRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		sendError(conn, fmt.Sprintf("bad request: %v", err))
		return
	}

	// Ensure clean state before running
	Cleanup()
	defer Cleanup()

	res := executeTest(req)

	if err := json.NewEncoder(conn).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "write response error: %v\n", err)
	}
}

func executeTest(req model.WorkerRequest) model.WorkerResult {
	if err := SetupIptables(req.TargetGroup); err != nil {
		return model.WorkerResult{Error: fmt.Sprintf("iptables: %v", err)}
	}

	cmd, stdout := StartNFQWS(req.StrategyArgs)
	if cmd == nil {
		return model.WorkerResult{Error: "nfqws start failed"}
	}
	defer KillCmd(cmd)

	// Short delay to let nfqws initialize
	time.Sleep(50 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return model.WorkerResult{Error: fmt.Sprintf("nfqws crashed: %s", stdout.String())}
	}

	v := verifier.NewVerifier(req.TargetGroup)
	ctx, cancel := context.WithTimeout(context.Background(), model.CheckTimeout)
	defer cancel()

	checkRes := v.Run(ctx)

	return model.WorkerResult{
		Success:      checkRes.Success,
		SuccessCount: checkRes.SuccessCount,
		TotalCount:   checkRes.TotalCount,
		Passed:       checkRes.PassedUrls,
		Failed:       checkRes.FailedUrls,
	}
}

func sendError(conn net.Conn, msg string) {
	_ = json.NewEncoder(conn).Encode(model.WorkerResult{Error: msg})
}

func fatalJSON(err string) {
	_ = json.NewEncoder(os.Stdout).Encode(model.WorkerResult{Error: err})
	os.Exit(1)
}
