package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"prikop/internal/model"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func DiscoverBinFiles(ctx context.Context, cli *client.Client, fakePath string) ([]string, error) {
	resp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      model.ImageName,
			Entrypoint: []string{"/bin/sh", "-c", fmt.Sprintf("ls -1 %s/*.bin 2>/dev/null", fakePath)},
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true}) }()

	if _, err := cli.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return nil, err
	}

	statusCh := cli.ContainerWait(ctx, resp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-statusCh.Error:
		return nil, err
	case <-statusCh.Result:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, client.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer out.Close()

	var buf bytes.Buffer
	stdcopy.StdCopy(&buf, io.Discard, out)

	var files []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			files = append(files, strings.TrimSpace(l))
		}
	}
	return files, nil
}

func RunContainerTest(ctx context.Context, cli *client.Client, args string, targetGroup string) (model.WorkerResult, string) {
	config := &container.Config{
		Image: model.ImageName,
		Cmd:   []string{"worker", args, targetGroup},
		Tty:   false,
	}
	hostConfig := &container.HostConfig{
		CapAdd:      []string{"NET_ADMIN"},
		NetworkMode: "bridge",
	}

	createResp, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: config, HostConfig: hostConfig})
	if err != nil {
		return model.WorkerResult{Error: "Docker Create: " + err.Error()}, ""
	}
	defer cli.ContainerRemove(context.Background(), createResp.ID, client.ContainerRemoveOptions{Force: true})

	if _, err := cli.ContainerStart(ctx, createResp.ID, client.ContainerStartOptions{}); err != nil {
		return model.WorkerResult{Error: "Docker Start: " + err.Error()}, ""
	}

	waitRes := cli.ContainerWait(ctx, createResp.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case <-waitRes.Result:
	case <-ctx.Done():
		return model.WorkerResult{Error: "Timeout"}, ""
	}

	out, err := cli.ContainerLogs(ctx, createResp.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return model.WorkerResult{Error: "Docker Logs Error: " + err.Error()}, ""
	}
	defer out.Close()

	var stdout, stderr bytes.Buffer
	stdcopy.StdCopy(&stdout, &stderr, out)

	var res model.WorkerResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return model.WorkerResult{Error: "JSON Error: " + err.Error()}, stderr.String()
	}
	return res, stderr.String()
}
