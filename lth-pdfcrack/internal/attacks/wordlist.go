package attacks

import (
	"bufio"
	"context"
	"os"
)

func WordlistGenerator(ctx context.Context, filename string) (<-chan string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	
	ch := make(chan string, 1000)
	
	go func() {
		defer close(ch)
		defer f.Close()
		
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case ch <- scanner.Text():
			}
		}
	}()
	
	return ch, nil
}

func SliceGenerator(ctx context.Context, passwords []string) <-chan string {
	ch := make(chan string, 100)
	
	go func() {
		defer close(ch)
		for _, p := range passwords {
			select {
			case <-ctx.Done():
				return
			case ch <- p:
			}
		}
	}()
	
	return ch
}
