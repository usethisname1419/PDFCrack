package attacks

import (
	"context"
	"math/rand"
	"time"
)

type RandomConfig struct {
	Charset   string
	MinLength int
	MaxLength int
	Seed      int64
}

func RandomGenerator(ctx context.Context, config RandomConfig) <-chan string {
	ch := make(chan string, 10000)
	
	go func() {
		defer close(ch)
		
		charset := []byte(config.Charset)
		if len(charset) == 0 {
			charset = []byte(CharsetAlphaNum)
		}
		
		minLen := config.MinLength
		if minLen < 1 {
			minLen = 1
		}
		
		maxLen := config.MaxLength
		if maxLen < minLen {
			maxLen = minLen
		}
		
		seed := config.Seed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		rng := rand.New(rand.NewSource(seed))
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			length := minLen
			if maxLen > minLen {
				length = minLen + rng.Intn(maxLen-minLen+1)
			}
			
			password := make([]byte, length)
			for i := range password {
				password[i] = charset[rng.Intn(len(charset))]
			}
			
			select {
			case <-ctx.Done():
				return
			case ch <- string(password):
			}
		}
	}()
	
	return ch
}
