package container

import (
	"bytes"
	"context"
	"fmt"
	"prikop/internal/model"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// DiscoverBinFiles runs a one-off container to list files in fake directory
func DiscoverBinFiles(ctx context.Context, cli *client.Client, path string) ([]string, error) {
	// We use 'find' to get full paths and robust file listing.
	// IMPORTANT: We must override Entrypoint because the image has ENTRYPOINT ["/usr/bin/prikop"]
	// If we don't, it runs 'prikop find ...' which triggers the orchestrator recursively and crashes.
	cmd := []string{"find", path, "-maxdepth", "1", "-name", "*.bin"}

	createOpts := client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      model.ImageName,
			Entrypoint: cmd, // Explicitly override ENTRYPOINT to bypass the binary
			Cmd:        nil, // Clear Cmd
			Tty:        false,
		},
	}

	resp, err := cli.ContainerCreate(ctx, createOpts)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	defer func() {
		_, _ = cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
	}()

	if _, err := cli.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}

	waitRes := cli.ContainerWait(ctx, resp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})

	select {
	case err := <-waitRes.Error:
		return nil, fmt.Errorf("wait error: %w", err)
	case <-waitRes.Result:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return nil, fmt.Errorf("logs error: %w", err)
	}
	defer out.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, out); err != nil {
		return nil, fmt.Errorf("stdcopy error: %w", err)
	}

	if stderr.Len() > 0 {
		return nil, fmt.Errorf("find command error: %s", stderr.String())
	}

	var bins []string
	for _, f := range strings.Split(stdout.String(), "\n") {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			bins = append(bins, trimmed)
		}
	}
	return bins, nil
}
