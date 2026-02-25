package pdf

import (
	"bytes"
	"testing"
)

func TestPadPassword(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 32},
		{"test", 32},
		{"12345678901234567890123456789012", 32},
		{"1234567890123456789012345678901234567890", 32},
	}

	for _, tt := range tests {
		result := padPassword([]byte(tt.input))
		if len(result) != tt.expected {
			t.Errorf("padPassword(%q) = len %d, want %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestRC4Encrypt(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	data := []byte("test data")
	
	encrypted := rc4Encrypt(key, data)
	decrypted := rc4Encrypt(key, encrypted)
	
	if !bytes.Equal(data, decrypted) {
		t.Errorf("RC4 round-trip failed: got %v, want %v", decrypted, data)
	}
}

func TestParseHexOrLiteral(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"48656C6C6F", []byte("Hello")},
		{"deadbeef", []byte{0xde, 0xad, 0xbe, 0xef}},
	}

	for _, tt := range tests {
		result := parseHexOrLiteral([]byte(tt.input))
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("parseHexOrLiteral(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestUnescapePDFString(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{`hello`, []byte("hello")},
		{`hel\nlo`, []byte("hel\nlo")},
		{`hel\\lo`, []byte("hel\\lo")},
		{`\101\102\103`, []byte("ABC")},
	}

	for _, tt := range tests {
		result := unescapePDFString([]byte(tt.input))
		if !bytes.Equal(result, tt.expected) {
			t.Errorf("unescapePDFString(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func BenchmarkCheckPasswordRC4(b *testing.B) {
	info := &EncryptionInfo{
		Version:     2,
		Revision:    3,
		Length:      128,
		Permissions: -3904,
		OwnerHash:   make([]byte, 32),
		UserHash:    make([]byte, 32),
		FileID:      make([]byte, 16),
		IsAES:       false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		info.CheckPassword("testpassword")
	}
}

func BenchmarkCheckPasswordAES(b *testing.B) {
	info := &EncryptionInfo{
		Version:     4,
		Revision:    4,
		Length:      128,
		Permissions: -3904,
		OwnerHash:   make([]byte, 32),
		UserHash:    make([]byte, 32),
		FileID:      make([]byte, 16),
		IsAES:       true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		info.CheckPassword("testpassword")
	}
}
