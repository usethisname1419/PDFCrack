package cracker

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lth/pdfcrack/internal/pdf"
)

type Result struct {
	Found     bool
	Password  string
	Attempts  uint64
	Duration  time.Duration
}

type Progress struct {
	Attempts    uint64
	Rate        float64
	Current     string
	ElapsedTime time.Duration
}

type Cracker struct {
	encInfo     *pdf.EncryptionInfo
	workers     int
	attempts    uint64
	startTime   time.Time
	progressCb  func(Progress)
	mu          sync.Mutex
}

func New(encInfo *pdf.EncryptionInfo, workers int) *Cracker {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Cracker{
		encInfo: encInfo,
		workers: workers,
	}
}

func (c *Cracker) SetProgressCallback(cb func(Progress)) {
	c.progressCb = cb
}

func (c *Cracker) Workers() int {
	return c.workers
}

func (c *Cracker) reportProgress(current string) {
	if c.progressCb == nil {
		return
	}
	
	attempts := atomic.LoadUint64(&c.attempts)
	elapsed := time.Since(c.startTime)
	rate := float64(attempts) / elapsed.Seconds()
	
	c.progressCb(Progress{
		Attempts:    attempts,
		Rate:        rate,
		Current:     current,
		ElapsedTime: elapsed,
	})
}

func (c *Cracker) CrackWithWordlist(ctx context.Context, passwords <-chan string) Result {
	c.startTime = time.Now()
	atomic.StoreUint64(&c.attempts, 0)
	
	resultChan := make(chan string, 1)
	doneChan := make(chan struct{})
	
	var wg sync.WaitGroup
	
	for i := 0; i < c.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-doneChan:
					return
				case password, ok := <-passwords:
					if !ok {
						return
					}
					
					atomic.AddUint64(&c.attempts, 1)
					
					if c.encInfo.CheckPassword(password) {
						select {
						case resultChan <- password:
							close(doneChan)
						default:
						}
						return
					}
					
					if atomic.LoadUint64(&c.attempts)%1000 == 0 {
						c.reportProgress(password)
					}
				}
			}
		}()
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	password, found := <-resultChan
	
	return Result{
		Found:    found,
		Password: password,
		Attempts: atomic.LoadUint64(&c.attempts),
		Duration: time.Since(c.startTime),
	}
}

func (c *Cracker) CrackWithGenerator(ctx context.Context, generator func(ctx context.Context) <-chan string) Result {
	passwords := generator(ctx)
	return c.CrackWithWordlist(ctx, passwords)
}

func (c *Cracker) TryPassword(password string) bool {
	atomic.AddUint64(&c.attempts, 1)
	return c.encInfo.CheckPassword(password)
}

func (c *Cracker) Attempts() uint64 {
	return atomic.LoadUint64(&c.attempts)
}
