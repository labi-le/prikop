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
	"prikop/internal/verifier/tcp16_20"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog"
)

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
	Name       string
	SocketPath string
	conn       net.Conn
	enc        *json.Encoder
	dec        *json.Decoder
}

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
	sem := make(chan struct{}, 10)

	for i := 0; i < p.size; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := fmt.Sprintf("prikop-worker-%d", idx)
			id := fmt.Sprintf("worker_%d", idx)
			socketPath := filepath.Join(model.SocketDir, id+".sock")

			p.mu.Lock()
			p.socketPaths = append(p.socketPaths, socketPath)
			p.mu.Unlock()

			w, err := p.spawnWorker(name, id, socketPath)
			if err != nil {
				p.log.Error().Err(err).Str("worker", id).Msg("Failed to spawn worker")
				errChan <- fmt.Errorf("worker %d: %w", idx, err)
				return
			}

			p.workers <- w
			p.log.Debug().Str("worker", id).Msg("Worker started")
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

func (p *WorkerPool) spawnWorker(name, id, socketPath string) (*Worker, error) {
	log := p.log.With().Str("worker", id).Logger()

	sockPathInner := filepath.Join(model.SocketDir, id+".sock")

	_ = os.Remove(socketPath)
	_, _ = p.cli.ContainerRemove(p.ctx, name, client.ContainerRemoveOptions{Force: true})

	createOpts := client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image: model.ImageName,
			Cmd:   []string{"-worker-socket", sockPathInner},
			Env:   []string{fmt.Sprintf("GOMEMLIMIT=%d", model.WorkerMemoryLimit*9/10)},
			Tty:   false,
		},
		HostConfig: &container.HostConfig{
			CapAdd: []string{"NET_ADMIN"},
			Resources: container.Resources{
				Memory: model.WorkerMemoryLimit,
			},
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: p.hostSockDir,
					Target: model.SocketDir,
				},
				{
					Type:   mount.TypeBind,
					Source: p.hostTargetsDir,
					Target: tcp16_20.TargetsDir,
				},
			},
			AutoRemove: true,
		},
	}

	resp, err := p.cli.ContainerCreate(p.ctx, createOpts)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	p.mu.Lock()
	p.containers = append(p.containers, resp.ID)
	p.mu.Unlock()

	if _, err := p.cli.ContainerStart(p.ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}

	if err := p.waitForSocket(log, socketPath, resp.ID); err != nil {
		return nil, fmt.Errorf("wait socket: %w", err)
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return &Worker{
		ID:         id,
		Name:       name,
		SocketPath: socketPath,
		conn:       conn,
		enc:        json.NewEncoder(conn),
		dec:        json.NewDecoder(conn),
	}, nil
}

func (p *WorkerPool) respawnWorker(old *Worker) {
	if p.ctx.Err() != nil {
		return
	}

	log := p.log.With().Str("worker", old.ID).Logger()
	log.Info().Msg("Respawning worker")

	w, err := p.spawnWorker(old.Name, old.ID, old.SocketPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to respawn worker")
		return
	}

	p.workers <- w
	log.Info().Msg("Worker respawned")
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

	close(p.workers)
	for w := range p.workers {
		w.conn.Close()
	}

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
			p.log.Warn().Err(err).Str("path", path).Msg("Failed to remove worker socket")
		}
	}
}

func (p *WorkerPool) Exec(ctx context.Context, req model.WorkerRequest) (model.WorkerResult, error) {
	select {
	case w := <-p.workers:
		res, err := w.exec(req)
		if err != nil {
			w.conn.Close()
			p.log.Warn().Str("worker", w.ID).Err(err).Msg("Worker failed, respawning")
			go p.respawnWorker(w)
			return model.WorkerResult{}, err
		}

		p.workers <- w
		return res, nil

	case <-ctx.Done():
		return model.WorkerResult{}, ctx.Err()
	}
}

func (w *Worker) exec(req model.WorkerRequest) (model.WorkerResult, error) {
	w.conn.SetDeadline(time.Now().Add(model.ContainerTimeout + 2*time.Second))

	if err := w.enc.Encode(req); err != nil {
		return model.WorkerResult{}, fmt.Errorf("send req to %s: %w", w.ID, err)
	}

	var res model.WorkerResult
	if err := w.dec.Decode(&res); err != nil {
		return model.WorkerResult{}, fmt.Errorf("read res from %s: %w", w.ID, err)
	}

	return res, nil
}
