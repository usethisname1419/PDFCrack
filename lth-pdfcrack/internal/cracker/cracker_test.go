package cracker

import (
	"context"
	"testing"
	"time"

	"github.com/lth/pdfcrack/internal/pdf"
)

func TestCrackerCreation(t *testing.T) {
	info := &pdf.EncryptionInfo{
		Version:  2,
		Revision: 3,
		Length:   128,
	}

	c := New(info, 4)
	if c.Workers() != 4 {
		t.Errorf("Workers() = %d, want 4", c.Workers())
	}

	c = New(info, 0)
	if c.Workers() <= 0 {
		t.Error("Workers() should be > 0 when given 0")
	}
}

func TestCrackerProgress(t *testing.T) {
	info := &pdf.EncryptionInfo{
		Version:   2,
		Revision:  3,
		Length:    128,
		OwnerHash: make([]byte, 32),
		UserHash:  make([]byte, 32),
		FileID:    make([]byte, 16),
	}

	c := New(info, 2)

	progressCalled := false
	c.SetProgressCallback(func(p Progress) {
		progressCalled = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	passwords := make(chan string, 100)
	for i := 0; i < 100; i++ {
		passwords <- "test"
	}
	close(passwords)

	c.CrackWithWordlist(ctx, passwords)

	if c.Attempts() == 0 {
		t.Error("Attempts() should be > 0 after cracking")
	}
}

func BenchmarkCracker(b *testing.B) {
	info := &pdf.EncryptionInfo{
		Version:     2,
		Revision:    3,
		Length:      128,
		Permissions: -3904,
		OwnerHash:   make([]byte, 32),
		UserHash:    make([]byte, 32),
		FileID:      make([]byte, 16),
	}

	c := New(info, 4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.TryPassword("testpassword123")
	}
}
