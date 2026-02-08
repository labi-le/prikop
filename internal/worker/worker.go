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
func RunWorkerServer(ctx context.Context, socketPath string) {
	// Initialize Providers without fetching CIDRs (Performance optimization for workers)
	if _, err := verifier.InitializeProviders(false); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to init providers: %v\n", err)
	} else {
		fmt.Println("Worker initialized providers")
	}

	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fatalJSON(fmt.Sprintf("listen error: %v", err))
	}
	if err := os.Chmod(socketPath, 0777); err != nil {
		fmt.Fprintf(os.Stderr, "chmod warning: %v\n", err)
	}

	fmt.Printf("Worker listening on %s\n", socketPath)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}
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
		FailureType:  checkRes.FailureReason,
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
