package scout

import (
	"context"
	"strings"

	"prikop/internal/container"
	"prikop/internal/model"

	"github.com/rs/zerolog"
)

// Group is the target group used for network probing.
var Group = "google_tcp"

// RunScout performs active reconnaissance (middlebox fingerprinting).
func RunScout(ctx context.Context, pool *container.WorkerPool, log zerolog.Logger) model.ReconReport {
	log.Info().Msg("Starting active reconnaissance...")
	r := model.ReconReport{}

	// 1. Check Fragmentation (ipfrag1)
	log.Info().Msg("Probing Fragmentation (ipfrag1)...")

	fragReq := model.WorkerRequest{
		StrategyArgs: strings.Fields("--dpi-desync=ipfrag1 --dpi-desync-repeats=2"),
		TargetGroup:  Group,
	}

	fragRes, err := pool.Exec(ctx, fragReq)
	if err == nil && fragRes.Success {
		log.Info().Msg("Fragmentation probe works (High Priority)")
		r.IPFragWorks = true
	} else {
		if err != nil {
			log.Error().Err(err).Msg("Fragmentation probe failed")
		} else {
			log.Warn().Msg("Fragmentation probe shows no effect (Pruning ipfrag1)")
		}
		r.IPFragWorks = false
	}

	// 2. Check BadSum
	log.Info().Msg("Probing BadSum (fake+badsum)...")

	badsumReq := model.WorkerRequest{
		StrategyArgs: strings.Fields("--dpi-desync=fake --dpi-desync-fooling=badsum"),
		TargetGroup:  Group,
	}

	badsumRes, err := pool.Exec(ctx, badsumReq)
	if err == nil && badsumRes.Success {
		log.Info().Msg("BadSum probe works (Will Boost)")
		r.BadSumWorks = true
	} else {
		if err != nil {
			log.Error().Err(err).Msg("BadSum probe failed")
		} else {
			log.Warn().Msg("BadSum probe shows no effect (Standard probability)")
		}
		r.BadSumWorks = false
	}

	return r
}
