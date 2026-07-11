package container

import (
	"net"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

func newTestPool(size int) *WorkerPool {
	return &WorkerPool{
		cancel:  func() {},
		workers: make(chan *Worker, size),
		log:     zerolog.Nop(),
	}
}

func fillWorkers(t *testing.T, p *WorkerPool, n int) {
	t.Helper()
	for range n {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { _ = c2.Close() })
		p.workers <- &Worker{conn: c1}
	}
}

// TestWorkerPoolShutdownRaceFree exercises the shutdown path that previously
// panicked: an in-flight Exec returning a worker (putWorker) could send on the
// channel after Stop had closed it. Run with -race.
func TestWorkerPoolShutdownRaceFree(t *testing.T) {
	const size = 16
	p := newTestPool(size)
	fillWorkers(t, p, size)

	var wg sync.WaitGroup

	// Takers continuously check a worker out and return it until shutdown.
	for range size {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				w, ok := <-p.workers
				if !ok {
					return
				}
				p.putWorker(w)
			}
		}()
	}

	// Concurrent shutdown must neither panic nor deadlock.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.closeWorkers()
	}()

	wg.Wait()

	if !p.isClosed() {
		t.Fatal("pool should be closed after closeWorkers")
	}
}

func TestPutWorkerAfterCloseClosesConn(t *testing.T) {
	p := newTestPool(4)
	if _, _, already := p.closeWorkers(); already {
		t.Fatal("first closeWorkers reported alreadyClosed")
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	p.putWorker(&Worker{conn: c1})

	// Nothing may have been sent onto the closed channel.
	if _, ok := <-p.workers; ok {
		t.Fatal("putWorker sent a worker onto a closed pool")
	}
	// The returned worker's conn must have been closed instead.
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Fatal("expected conn to be closed by putWorker")
	}
}

func TestCloseWorkersIdempotent(t *testing.T) {
	p := newTestPool(2)
	if _, _, already := p.closeWorkers(); already {
		t.Fatal("first close reported alreadyClosed")
	}
	if _, _, already := p.closeWorkers(); !already {
		t.Fatal("second close should report alreadyClosed")
	}
}
