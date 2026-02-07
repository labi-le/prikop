package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"prikop/internal/model"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// WorkerPool manages a pool of long-lived worker containers
type WorkerPool struct {
	cli         *client.Client
	ctx         context.Context
	size        int
	workers     chan *Worker
	containers  []string
	socketPaths []string // Track created sockets for cleanup
	mu          sync.Mutex
	hostSockDir string
}

type Worker struct {
	ID         string
	SocketPath string
}

// NewWorkerPool initializes the pool.
func NewWorkerPool(ctx context.Context, cli *client.Client, size int, hostSockDir string) *WorkerPool {
	return &WorkerPool{
		cli:         cli,
		ctx:         ctx,
		size:        size,
		workers:     make(chan *Worker, size),
		containers:  make([]string, 0, size),
		socketPaths: make([]string, 0, size),
		hostSockDir: hostSockDir,
	}
}

func (p *WorkerPool) Start() error {
	fmt.Printf("Initializing pool with %d workers. Host socket dir: %s\n", p.size, p.hostSockDir)

	var wg sync.WaitGroup
	errChan := make(chan error, p.size)

	sem := make(chan struct{}, 10)

	for i := 0; i < p.size; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			workerName := fmt.Sprintf("prikop-worker-%d", idx)
			workerID := fmt.Sprintf("worker_%d", idx)

			sockPathInner := filepath.Join(model.SocketDir, workerID+".sock")
			sockPathOrchestrator := filepath.Join(model.SocketDir, workerID+".sock")

			// Register socket path for cleanup immediately
			p.mu.Lock()
			p.socketPaths = append(p.socketPaths, sockPathOrchestrator)
			p.mu.Unlock()

			// Cleanup potential stale socket before starting
			_ = os.Remove(sockPathOrchestrator)
			_, _ = p.cli.ContainerRemove(p.ctx, workerName, client.ContainerRemoveOptions{Force: true})

			createOpts := client.ContainerCreateOptions{
				Name: workerName,
				Config: &container.Config{
					Image: model.ImageName,
					Cmd:   []string{"-worker-socket", sockPathInner},
					Tty:   false,
				},
				HostConfig: &container.HostConfig{
					CapAdd: []string{"NET_ADMIN"},
					Mounts: []mount.Mount{
						{
							Type:   mount.TypeBind,
							Source: p.hostSockDir,
							Target: model.SocketDir,
						},
					},
					AutoRemove: true,
				},
			}

			resp, err := p.cli.ContainerCreate(p.ctx, createOpts)
			if err != nil {
				errChan <- fmt.Errorf("create worker %d: %w", idx, err)
				return
			}

			p.mu.Lock()
			p.containers = append(p.containers, resp.ID)
			p.mu.Unlock()

			if _, err := p.cli.ContainerStart(p.ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
				errChan <- fmt.Errorf("start worker %d: %w", idx, err)
				return
			}

			if err := p.waitForSocket(sockPathOrchestrator, resp.ID); err != nil {
				errChan <- fmt.Errorf("worker %d failed to start: %w", idx, err)
				return
			}

			p.workers <- &Worker{
				ID:         workerID,
				SocketPath: sockPathOrchestrator,
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		p.Stop()
		return <-errChan
	}
	return nil
}

func (p *WorkerPool) waitForSocket(path string, containerID string) error {
	for i := 0; i < 300; i++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}

		if i%10 == 0 {
			insp, err := p.cli.ContainerInspect(p.ctx, containerID, client.ContainerInspectOptions{})
			if err == nil && !insp.Container.State.Running {
				logs, _ := p.cli.ContainerLogs(p.ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
				var buf bytes.Buffer
				stdcopy.StdCopy(&buf, &buf, logs)
				return fmt.Errorf("worker died early (ExitCode: %d). Logs: %s", insp.Container.State.ExitCode, buf.String())
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("socket %s not created (timeout)", path)
}

func (p *WorkerPool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	ctx := context.Background()
	var wg sync.WaitGroup

	for _, cid := range p.containers {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, _ = p.cli.ContainerRemove(tCtx, id, client.ContainerRemoveOptions{Force: true})
		}(cid)
	}
	wg.Wait()

	for _, path := range p.socketPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Warning: failed to remove socket %s: %v\n", path, err)
		}
	}
}

func (p *WorkerPool) Exec(ctx context.Context, req model.WorkerRequest) (model.WorkerResult, error) {
	select {
	case w := <-p.workers:
		defer func() { p.workers <- w }()

		d := net.Dialer{Timeout: 1 * time.Second}
		conn, err := d.DialContext(ctx, "unix", w.SocketPath)
		if err != nil {
			return model.WorkerResult{}, fmt.Errorf("dial worker %s: %w", w.ID, err)
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(model.ContainerTimeout + 2*time.Second))

		if err := json.NewEncoder(conn).Encode(req); err != nil {
			return model.WorkerResult{}, fmt.Errorf("send req: %w", err)
		}

		var res model.WorkerResult
		if err := json.NewDecoder(conn).Decode(&res); err != nil {
			return model.WorkerResult{}, fmt.Errorf("read res: %w", err)
		}

		return res, nil

	case <-ctx.Done():
		return model.WorkerResult{}, ctx.Err()
	}
}
