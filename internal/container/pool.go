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
	"prikop/internal/verifier"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog"
)

// WorkerPool manages a pool of long-lived worker containers
type WorkerPool struct {
	cli            *client.Client
	ctx            context.Context
	size           int
	workers        chan *Worker
	containers     []string
	socketPaths    []string
	mu             sync.Mutex
	hostSockDir    string
	hostTargetsDir string
	log            zerolog.Logger
}

type Worker struct {
	ID         string
	SocketPath string
}

// NewWorkerPool initializes the pool.
func NewWorkerPool(ctx context.Context, cli *client.Client, size int, hostSockDir string, hostTargetsDir string, log zerolog.Logger) *WorkerPool {
	return &WorkerPool{
		cli:            cli,
		ctx:            ctx,
		size:           size,
		workers:        make(chan *Worker, size),
		containers:     make([]string, 0, size),
		socketPaths:    make([]string, 0, size),
		hostSockDir:    hostSockDir,
		hostTargetsDir: hostTargetsDir,
		log:            log,
	}
}

func (p *WorkerPool) Start() error {
	p.log.Info().Int("size", p.size).Str("socket_dir", p.hostSockDir).Str("targets_dir", p.hostTargetsDir).Msg("Initializing worker pool")

	var wg sync.WaitGroup
	errChan := make(chan error, p.size)
	// Semaphore to limit concurrent container creation API calls
	sem := make(chan struct{}, 10)

	for i := 0; i < p.size; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			workerName := fmt.Sprintf("prikop-worker-%d", idx)
			workerID := fmt.Sprintf("worker_%d", idx)
			log := p.log.With().Str("worker_name", workerName).Int("worker_idx", idx).Logger()

			sockPathInner := filepath.Join(model.SocketDir, workerID+".sock")
			sockPathOrchestrator := filepath.Join(model.SocketDir, workerID+".sock")

			// Register socket path for cleanup immediately
			p.mu.Lock()
			p.socketPaths = append(p.socketPaths, sockPathOrchestrator)
			p.mu.Unlock()

			// Cleanup potential stale socket/container
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
						{
							Type:   mount.TypeBind,
							Source: p.hostTargetsDir,
							Target: verifier.TargetsDir,
						},
					},
					AutoRemove: true,
				},
			}

			resp, err := p.cli.ContainerCreate(p.ctx, createOpts)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create worker container")
				errChan <- fmt.Errorf("create worker %d: %w", idx, err)
				return
			}

			p.mu.Lock()
			p.containers = append(p.containers, resp.ID)
			p.mu.Unlock()

			if _, err := p.cli.ContainerStart(p.ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
				log.Error().Err(err).Msg("Failed to start worker container")
				errChan <- fmt.Errorf("start worker %d: %w", idx, err)
				return
			}

			if err := p.waitForSocket(log, sockPathOrchestrator, resp.ID); err != nil {
				log.Error().Err(err).Msg("Worker failed to become ready")
				errChan <- fmt.Errorf("worker %d failed to start: %w", idx, err)
				return
			}

			p.workers <- &Worker{
				ID:         workerID,
				SocketPath: sockPathOrchestrator,
			}
			log.Debug().Msg("Worker started successfully")
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

func (p *WorkerPool) waitForSocket(log zerolog.Logger, path string, containerID string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("socket %s not created (timeout/cancelled)", path)
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				return nil
			}

			// Check if container died
			insp, err := p.cli.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
			if err == nil && !insp.Container.State.Running {
				logs, logErr := p.cli.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
				if logErr != nil {
					log.Warn().Err(logErr).Msg("Failed to retrieve container logs")
				}
				var buf bytes.Buffer
				if logs != nil {
					stdcopy.StdCopy(&buf, &buf, logs)
				}
				log.Error().Int("exit_code", insp.Container.State.ExitCode).Str("logs", buf.String()).Msg("Worker container died early")
				return fmt.Errorf("worker died early (ExitCode: %d)", insp.Container.State.ExitCode)
			}
		}
	}
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
			// Ignore errors on removal
			_, _ = p.cli.ContainerRemove(tCtx, id, client.ContainerRemoveOptions{Force: true})
		}(cid)
	}
	wg.Wait()

	for _, path := range p.socketPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			p.log.Warn().Err(err).Str("path", path).Msg("Failed to remove worker socket")
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
