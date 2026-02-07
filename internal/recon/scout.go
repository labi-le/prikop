package recon

import (
	"context"
	"fmt"

	"prikop/internal/container"
	"prikop/internal/model"

	"github.com/moby/moby/client"
)

// RunScout performs active reconnaissance (middlebox fingerprinting)
func RunScout(ctx context.Context, cli *client.Client, group string) model.ReconReport {
	fmt.Println(">>> STARTING ACTIVE RECONNAISSANCE...")
	r := model.ReconReport{}

	// 1. Check Fragmentation (ipfrag1)
	// Heuristic: Does the DPI reassemble IP fragments?
	// If ipfrag1 works, it's a very strong candidate. If it fails, we prune it to save time.
	fmt.Print("    [?] Probing Fragmentation (ipfrag1)... ")
	// Using repeats=2 to ensure stability
	fragRes, _ := container.RunContainerTest(ctx, cli, "--dpi-desync=ipfrag1 --dpi-desync-repeats=2", group)
	if fragRes.Success {
		fmt.Println("WORKS (High Priority)")
		r.IPFragWorks = true
	} else {
		fmt.Println("FAILED (Pruning ipfrag1)")
		r.IPFragWorks = false
	}

	// 2. Check BadSum
	// Heuristic: Does the DPI drop packets with invalid TCP checksums?
	// We test 'fake' mode with 'badsum'. If it works, we can use BadSum to fool DPI.
	// If it fails (while we don't know if fake works yet), we treat it as "Risky/Ineffective" and don't enforce it.
	// However, if it SUCCEEDS, it's a huge signal.
	fmt.Print("    [?] Probing BadSum (fake+badsum)... ")
	badsumRes, _ := container.RunContainerTest(ctx, cli, "--dpi-desync=fake --dpi-desync-fooling=badsum", group)
	if badsumRes.Success {
		fmt.Println("WORKS (Will Boost)")
		r.BadSumWorks = true
	} else {
		// It might fail because 'fake' failed, or because 'badsum' was dropped.
		// We assume standard probability.
		fmt.Println("NO EFFECT/FAILED (Standard probability)")
		r.BadSumWorks = false
	}

	return r
}
