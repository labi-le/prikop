package recon

import (
	"context"
	"fmt"

	"prikop/internal/container"
	"prikop/internal/model"
)

// RunScout performs active reconnaissance (middlebox fingerprinting)
// Now uses WorkerPool for fast execution instead of spinning up new containers.
func RunScout(ctx context.Context, pool *container.WorkerPool, group string) model.ReconReport {
	fmt.Println(">>> STARTING ACTIVE RECONNAISSANCE...")
	r := model.ReconReport{}

	// 1. Check Fragmentation (ipfrag1)
	fmt.Print("    [?] Probing Fragmentation (ipfrag1)... ")

	fragReq := model.WorkerRequest{
		StrategyArgs: "--dpi-desync=ipfrag1 --dpi-desync-repeats=2",
		TargetGroup:  group,
	}

	fragRes, err := pool.Exec(ctx, fragReq)
	if err == nil && fragRes.Success {
		fmt.Println("WORKS (High Priority)")
		r.IPFragWorks = true
	} else {
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("FAILED (Pruning ipfrag1)")
		}
		r.IPFragWorks = false
	}

	// 2. Check BadSum
	fmt.Print("    [?] Probing BadSum (fake+badsum)... ")

	badsumReq := model.WorkerRequest{
		StrategyArgs: "--dpi-desync=fake --dpi-desync-fooling=badsum",
		TargetGroup:  group,
	}

	badsumRes, err := pool.Exec(ctx, badsumReq)
	if err == nil && badsumRes.Success {
		fmt.Println("WORKS (Will Boost)")
		r.BadSumWorks = true
	} else {
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Println("NO EFFECT/FAILED (Standard probability)")
		}
		r.BadSumWorks = false
	}

	return r
}
