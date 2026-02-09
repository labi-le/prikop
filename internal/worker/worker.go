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

	"github.com/rs/zerolog"
)

// RunWorkerServer starts the worker in listening mode
func RunWorkerServer(ctx context.Context, socketPath string, log zerolog.Logger) {
	// Initialize Providers without fetching CIDRs (Performance optimization for workers)
	if _, err := verifier.InitializeProviders(false, log); err != nil {
		log.Warn().Err(err).Msg("Failed to init providers")
	} else {
		log.Info().Msg("Worker initialized providers")
	}

	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Listen error")
	}
	if err := os.Chmod(socketPath, 0777); err != nil {
		log.Warn().Err(err).Msg("chmod failed")
	}

	log.Info().Str("socket", socketPath).Msg("Worker listening")

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
			log.Error().Err(err).Msg("Accept error")
			continue
		}
		go handleConnection(conn, log)
	}
}

func handleConnection(conn net.Conn, log zerolog.Logger) {
	defer conn.Close()

	var req model.WorkerRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		sendError(conn, fmt.Sprintf("bad request: %v", err))
		return
	}

	Cleanup()
	defer Cleanup()

	res := executeTest(req, log.With().Str("group", req.TargetGroup).Logger())

	if err := json.NewEncoder(conn).Encode(res); err != nil {
		log.Error().Err(err).Msg("Failed to write response")
	}
}

func executeTest(req model.WorkerRequest, log zerolog.Logger) model.WorkerResult {
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

	v := verifier.NewVerifier(req.TargetGroup, log) // Will require change in verifier
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

// fatalJSON is no longer used, replaced by direct log.Fatal()
