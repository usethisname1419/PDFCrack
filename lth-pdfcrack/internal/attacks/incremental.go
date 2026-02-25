package attacks

import (
	"context"
)

type IncrementalConfig struct {
	Charset   string
	MinLength int
	MaxLength int
}

var (
	CharsetLower   = "abcdefghijklmnopqrstuvwxyz"
	CharsetUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsetDigits  = "0123456789"
	CharsetSpecial = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	CharsetAlpha   = CharsetLower + CharsetUpper
	CharsetAlphaNum = CharsetAlpha + CharsetDigits
	CharsetAll     = CharsetAlphaNum + CharsetSpecial
)

func IncrementalGenerator(ctx context.Context, config IncrementalConfig) <-chan string {
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
		if maxLen > 16 {
			maxLen = 16
		}
		
		for length := minLen; length <= maxLen; length++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			if !generateLength(ctx, ch, charset, length) {
				return
			}
		}
	}()
	
	return ch
}

func generateLength(ctx context.Context, ch chan<- string, charset []byte, length int) bool {
	indices := make([]int, length)
	password := make([]byte, length)
	
	for i := range password {
		password[i] = charset[0]
	}
	
	for {
		select {
		case <-ctx.Done():
			return false
		case ch <- string(password):
		}
		
		pos := length - 1
		for pos >= 0 {
			indices[pos]++
			if indices[pos] < len(charset) {
				password[pos] = charset[indices[pos]]
				break
			}
			indices[pos] = 0
			password[pos] = charset[0]
			pos--
		}
		
		if pos < 0 {
			return true
		}
	}
}

func EstimateCombinations(config IncrementalConfig) uint64 {
	charset := config.Charset
	if charset == "" {
		charset = CharsetAlphaNum
	}
	
	var total uint64
	base := uint64(len(charset))
	
	for length := config.MinLength; length <= config.MaxLength; length++ {
		combinations := uint64(1)
		for i := 0; i < length; i++ {
			combinations *= base
		}
		total += combinations
	}
	
	return total
}
