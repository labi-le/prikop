package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"prikop/internal/container"
	"prikop/internal/evolution"
	"prikop/internal/galaxy"
	"prikop/internal/model"
	"prikop/internal/nfqws"
	"prikop/internal/recon"

	"github.com/moby/moby/client"
)

type Config struct {
	FakePath    string
	TargetsPath string
}

type Phase struct {
	Name    string
	Group   string
	Gens    int
	Filters string
}

func Run(cfg Config) {
	ctx := context.Background()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("Docker client: %v", err)
	}
	defer cli.Close()

	// 1. Discovery
	bins, err := container.DiscoverBinFiles(ctx, cli, cfg.FakePath)
	if err != nil {
		log.Fatalf("No bin files: %v", err)
	}
	fmt.Printf(">>> Found %d bin files\n", len(bins))

	phases := []Phase{
		{
			Name:    "GENERAL TCP (TCP 16-20 Checker)",
			Group:   "general",
			Gens:    10,
			Filters: "--filter-tcp=80,443",
		},
		{
			Name:    "GOOGLE TCP",
			Group:   "google_tcp",
			Gens:    10,
			Filters: fmt.Sprintf("--filter-tcp=80,443 --hostlist=%s/google.txt", cfg.TargetsPath),
		},
		{
			Name:    "GOOGLE UDP (QUIC)",
			Group:   "google_udp",
			Gens:    10,
			Filters: fmt.Sprintf("--filter-udp=443 --hostlist=%s/google.txt", cfg.TargetsPath),
		},
		{
			Name:    "DISCORD UDP (Voice)",
			Group:   "discord_udp",
			Gens:    10,
			Filters: fmt.Sprintf("--filter-udp=50000-65535,443 --hostlist=%s/discord.txt", cfg.TargetsPath),
		},
		{
			Name:    "DISCORD UDP (STUN)",
			Group:   "discord_l7",
			Gens:    10,
			Filters: fmt.Sprintf("--filter-udp=19294-19344 --filter-l7=discord,stun --hostlist=%s/discord.txt", cfg.TargetsPath),
		},
	}

	var finalConfigs []string

	for _, p := range phases {
		fmt.Printf("\n>>> PHASE: %s\n", p.Name)
		fmt.Printf(">>> Filters: %s\n", p.Filters)

		best := runPhase(ctx, cli, p.Group, bins, p.Gens)

		if best != nil {
			strategyArgs := best.Config.ToArgs()
			fmt.Printf(">>> WINNER: %s\n", strategyArgs)

			block := fmt.Sprintf("%s %s", p.Filters, strategyArgs)
			finalConfigs = append(finalConfigs, block)
		} else {
			fmt.Printf(">>> FAILED: No working strategy found for %s\n", p.Name)
		}
	}

	printFinalConfig(finalConfigs)
}

func printFinalConfig(configs []string) {
	fmt.Println("\n=======================================================")
	fmt.Println(">>> 🎉 FINAL CONFIGURATION")
	fmt.Println("=======================================================")

	if len(configs) == 0 {
		fmt.Println("# No working strategies found.")
		return
	}

	finalStr := strings.Join(configs, "\n--new\n")
	fmt.Println(finalStr)
	fmt.Println("\n=======================================================")
}

func runPhase(ctx context.Context, cli *client.Client, group string, bins []string, maxGens int) *model.ScoredStrategy {
	// 0. Active Reconnaissance (New Step)
	reconReport := recon.RunScout(ctx, cli, group)

	var population []nfqws.Strategy

	// Inject Recon Report into Sniper
	population = galaxy.GenerateZeroGeneration(bins, reconReport)

	var globalBest *model.ScoredStrategy

	for gen := 0; gen < maxGens; gen++ {
		fmt.Printf(">>> GEN %d/%d (%d strategies)\n", gen, maxGens, len(population))

		results := executeBatch(ctx, cli, population, group)

		sort.Slice(results, func(i, j int) bool {
			return evolution.CalculateScore(results[i].Result, results[i].Complexity) >
				evolution.CalculateScore(results[j].Result, results[j].Complexity)
		})

		if len(results) > 0 {
			bestGen := results[0]
			score := evolution.CalculateScore(bestGen.Result, bestGen.Complexity)

			if globalBest == nil || score > evolution.CalculateScore(globalBest.Result, globalBest.Complexity) {
				globalBest = &bestGen
				fmt.Printf(">>> NEW BEST: %s (Success: %d/%d)\n", globalBest.Config.ToArgs(), globalBest.Result.SuccessCount, globalBest.Result.TotalCount)

				if len(globalBest.Result.Passed) > 0 {
					fmt.Println("    [+] PASSED:")
					for _, u := range globalBest.Result.Passed {
						fmt.Printf("        %s\n", u)
					}
				}
				if len(globalBest.Result.Failed) > 0 {
					fmt.Println("    [-] FAILED:")
					for _, u := range globalBest.Result.Failed {
						fmt.Printf("        %s\n", u)
					}
				}
			}
		}

		if globalBest != nil && globalBest.Result.SuccessCount == globalBest.Result.TotalCount && gen > 3 {
			if globalBest.Complexity <= 2 {
				fmt.Println(">>> Ideal strategy found, skipping remaining generations.")
				break
			}
		}

		population = evolution.Evolve(results, bins)
		if len(population) == 0 {
			break
		}
	}

	return globalBest
}

func executeBatch(ctx context.Context, cli *client.Client, strats []nfqws.Strategy, group string) []model.ScoredStrategy {
	resultsCh := make(chan model.ScoredStrategy, len(strats))
	sem := make(chan struct{}, model.MaxWorkers)
	var wg sync.WaitGroup

	for _, s := range strats {
		wg.Add(1)
		go func(strat nfqws.Strategy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tCtx, cancel := context.WithTimeout(ctx, model.ContainerTimeout)
			defer cancel()

			args := strat.ToArgs()
			if args == "" {
				return
			}

			start := time.Now()
			wRes, logs := container.RunContainerTest(tCtx, cli, args, group)
			dur := time.Since(start)

			if wRes.Success {
				resultsCh <- model.ScoredStrategy{
					Config:     strat,
					RawArgs:    args,
					Duration:   dur,
					Result:     wRes,
					SystemLogs: logs,
					Complexity: strat.Repeats,
				}
			}
		}(s)
	}
	wg.Wait()
	close(resultsCh)

	var res []model.ScoredStrategy
	for r := range resultsCh {
		res = append(res, r)
	}
	return res
}
