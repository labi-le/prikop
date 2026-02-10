package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"prikop/internal/model"
	"prikop/internal/verifier"
	"time"

	"github.com/rs/zerolog"
)

func RunWorkerServer(ctx context.Context, socketPath string, log zerolog.Logger) {
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

	conn, err := listener.Accept()
	listener.Close()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Fatal().Err(err).Msg("Accept error")
	}
	defer conn.Close()

	log.Info().Msg("Client connected, serving requests")

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req model.WorkerRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			log.Error().Err(err).Msg("Decode error")
			return
		}

		Cleanup()
		res := executeTest(req, log.With().Str("group", req.TargetGroup).Logger())
		Cleanup()

		if err := enc.Encode(res); err != nil {
			log.Error().Err(err).Msg("Encode error")
			return
		}
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

	v := verifier.NewVerifier(req.TargetGroup, log)
	vCtx, cancel := context.WithTimeout(context.Background(), model.CheckTimeout)
	defer cancel()

	checkRes := v.Run(vCtx)

	return model.WorkerResult{
		Success:      checkRes.Success,
		FailureType:  checkRes.FailureReason,
		SuccessCount: checkRes.SuccessCount,
		TotalCount:   checkRes.TotalCount,
		Passed:       checkRes.PassedUrls,
		Failed:       checkRes.FailedUrls,
	}
}
