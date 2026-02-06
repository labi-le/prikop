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

// DiscoverBinFiles scans the container for .bin files in the fake directory
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
	defer func() {
		_, _ = cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
	}()

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
		return nil, err
	}
	defer out.Close()

	var buf bytes.Buffer
	stdcopy.StdCopy(&buf, io.Discard, out)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var files []string
	seen := make(map[string]struct{})
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasSuffix(l, ".bin") {
			if _, ok := seen[l]; !ok {
				seen[l] = struct{}{}
				files = append(files, l)
			}
		}
	}
	return files, nil
}

// RunContainerTest spins up a sibling container to execute the worker check
func RunContainerTest(ctx context.Context, cli *client.Client, strategy string, targetGroup string) (model.WorkerResult, string) {
	config := &container.Config{
		Image: model.ImageName,
		Cmd:   []string{"worker", strategy, targetGroup},
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
	containerID := createResp.ID
	defer func() {
		_, _ = cli.ContainerRemove(context.Background(), containerID, client.ContainerRemoveOptions{Force: true})
	}()

	if _, err := cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		return model.WorkerResult{Error: "Docker Start: " + err.Error()}, ""
	}

	waitRes := cli.ContainerWait(ctx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-waitRes.Error:
		if err != nil {
			return model.WorkerResult{Error: "Docker Wait: " + err.Error()}, ""
		}
	case <-waitRes.Result:
	}

	out, _ := cli.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	defer out.Close()
	var stdoutBuf, stderrBuf bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)

	stdoutStr := strings.TrimSpace(stdoutBuf.String())
	if stdoutStr == "" {
		return model.WorkerResult{Error: "Empty stdout"}, stderrBuf.String()
	}

	var res model.WorkerResult
	if err := json.Unmarshal([]byte(stdoutStr), &res); err != nil {
		return model.WorkerResult{Error: "JSON Parse: " + err.Error()}, stderrBuf.String()
	}
	return res, stderrBuf.String()
}
