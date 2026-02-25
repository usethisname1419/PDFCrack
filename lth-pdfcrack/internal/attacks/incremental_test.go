package attacks

import (
	"context"
	"testing"
	"time"
)

func TestIncrementalGenerator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config := IncrementalConfig{
		Charset:   "ab",
		MinLength: 1,
		MaxLength: 2,
	}

	ch := IncrementalGenerator(ctx, config)

	expected := []string{"a", "b", "aa", "ab", "ba", "bb"}
	var got []string

	for pwd := range ch {
		got = append(got, pwd)
		if len(got) >= len(expected) {
			break
		}
	}

	if len(got) != len(expected) {
		t.Fatalf("got %d passwords, want %d", len(got), len(expected))
	}

	for i, exp := range expected {
		if got[i] != exp {
			t.Errorf("password[%d] = %q, want %q", i, got[i], exp)
		}
	}
}

func TestEstimateCombinations(t *testing.T) {
	tests := []struct {
		config   IncrementalConfig
		expected uint64
	}{
		{IncrementalConfig{Charset: "ab", MinLength: 1, MaxLength: 1}, 2},
		{IncrementalConfig{Charset: "ab", MinLength: 1, MaxLength: 2}, 6},
		{IncrementalConfig{Charset: "abc", MinLength: 2, MaxLength: 2}, 9},
		{IncrementalConfig{Charset: "0123456789", MinLength: 4, MaxLength: 4}, 10000},
	}

	for _, tt := range tests {
		result := EstimateCombinations(tt.config)
		if result != tt.expected {
			t.Errorf("EstimateCombinations(%v) = %d, want %d", tt.config, result, tt.expected)
		}
	}
}

func BenchmarkIncrementalGenerator(b *testing.B) {
	ctx := context.Background()
	config := IncrementalConfig{
		Charset:   CharsetAlphaNum,
		MinLength: 1,
		MaxLength: 4,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := IncrementalGenerator(ctx, config)
		count := 0
		for range ch {
			count++
			if count >= 10000 {
				break
			}
		}
	}
}
