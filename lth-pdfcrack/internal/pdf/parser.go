package pdf

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type EncryptionInfo struct {
	Version       int
	Revision      int
	Length        int
	Permissions   int32
	OwnerHash     []byte
	UserHash      []byte
	FileID        []byte
	EncryptMeta   bool
	IsAES         bool
	PDFVersion    string
}

func (e *EncryptionInfo) String() string {
	return fmt.Sprintf("PDF %s, V%d R%d, %d-bit key, AES=%v", 
		e.PDFVersion, e.Version, e.Revision, e.Length, e.IsAES)
}

var (
	ErrNotEncrypted     = errors.New("PDF is not encrypted")
	ErrUnsupportedPDF   = errors.New("unsupported PDF encryption")
	ErrInvalidPDF       = errors.New("invalid PDF file")
)

func ExtractEncryptionInfo(filename string) (*EncryptionInfo, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, ErrInvalidPDF
	}

	info := &EncryptionInfo{}
	
	versionMatch := regexp.MustCompile(`%PDF-(\d+\.\d+)`).FindSubmatch(data)
	if versionMatch != nil {
		info.PDFVersion = string(versionMatch[1])
	}

	encryptMatch := regexp.MustCompile(`/Encrypt\s+(\d+)\s+\d+\s+R`).FindSubmatch(data)
	if encryptMatch == nil {
		encryptMatch = regexp.MustCompile(`/Encrypt\s*<<`).FindSubmatch(data)
		if encryptMatch == nil {
			return nil, ErrNotEncrypted
		}
	}

	if err := parseEncryptDict(data, info); err != nil {
		return nil, err
	}

	if err := parseFileID(data, info); err != nil {
		return nil, err
	}

	return info, nil
}

func parseEncryptDict(data []byte, info *EncryptionInfo) error {
	vMatch := regexp.MustCompile(`/V\s+(\d+)`).FindSubmatch(data)
	if vMatch != nil {
		info.Version, _ = strconv.Atoi(string(vMatch[1]))
	}

	rMatch := regexp.MustCompile(`/R\s+(\d+)`).FindSubmatch(data)
	if rMatch != nil {
		info.Revision, _ = strconv.Atoi(string(rMatch[1]))
	}

	lengthMatch := regexp.MustCompile(`/Length\s+(\d+)`).FindSubmatch(data)
	if lengthMatch != nil {
		info.Length, _ = strconv.Atoi(string(lengthMatch[1]))
	} else {
		info.Length = 40
	}

	pMatch := regexp.MustCompile(`/P\s+(-?\d+)`).FindSubmatch(data)
	if pMatch != nil {
		p, _ := strconv.ParseInt(string(pMatch[1]), 10, 32)
		info.Permissions = int32(p)
	}

	oMatch := regexp.MustCompile(`/O\s*[<(]([^>)]+)[>)]`).FindSubmatch(data)
	if oMatch != nil {
		info.OwnerHash = parseHexOrLiteral(oMatch[1])
	}

	uMatch := regexp.MustCompile(`/U\s*[<(]([^>)]+)[>)]`).FindSubmatch(data)
	if uMatch != nil {
		info.UserHash = parseHexOrLiteral(uMatch[1])
	}

	cfmMatch := regexp.MustCompile(`/CFM\s*/AESV[23]`).FindSubmatch(data)
	info.IsAES = cfmMatch != nil

	if info.Version == 0 {
		info.Version = 1
	}
	if info.Revision == 0 {
		info.Revision = 2
	}

	return nil
}

func parseFileID(data []byte, info *EncryptionInfo) error {
	idMatch := regexp.MustCompile(`/ID\s*\[\s*[<(]([^>)]+)[>)]\s*[<(]([^>)]+)[>)]`).FindSubmatch(data)
	if idMatch != nil {
		info.FileID = parseHexOrLiteral(idMatch[1])
	}
	return nil
}

func parseHexOrLiteral(data []byte) []byte {
	s := string(data)
	s = strings.TrimSpace(s)
	
	if len(s) > 0 && (s[0] >= '0' && s[0] <= '9' || s[0] >= 'a' && s[0] <= 'f' || s[0] >= 'A' && s[0] <= 'F') {
		result := make([]byte, 0, len(s)/2)
		for i := 0; i+1 < len(s); i += 2 {
			b, err := strconv.ParseUint(s[i:i+2], 16, 8)
			if err != nil {
				break
			}
			result = append(result, byte(b))
		}
		return result
	}
	
	return []byte(s)
}

var pdfPadding = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

func (info *EncryptionInfo) CheckPassword(password string) bool {
	if info.Revision <= 4 {
		return info.checkPasswordR4(password)
	}
	return false
}

func (info *EncryptionInfo) checkPasswordR4(password string) bool {
	paddedPassword := padPassword([]byte(password))
	
	h := md5.New()
	h.Write(paddedPassword)
	h.Write(info.OwnerHash)
	
	pBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pBytes, uint32(info.Permissions))
	h.Write(pBytes)
	
	h.Write(info.FileID)
	
	if info.Revision >= 4 && !info.EncryptMeta {
		h.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	}
	
	key := h.Sum(nil)
	
	keyLen := info.Length / 8
	if keyLen > 16 {
		keyLen = 16
	}
	if keyLen < 5 {
		keyLen = 5
	}
	
	if info.Revision >= 3 {
		for i := 0; i < 50; i++ {
			h2 := md5.New()
			h2.Write(key[:keyLen])
			key = h2.Sum(nil)
		}
	}
	
	key = key[:keyLen]
	
	return info.verifyUserPassword(key)
}

func (info *EncryptionInfo) verifyUserPassword(key []byte) bool {
	if info.Revision == 2 {
		encrypted := rc4Encrypt(key, pdfPadding)
		return bytes.Equal(encrypted, info.UserHash)
	}
	
	h := md5.New()
	h.Write(pdfPadding)
	h.Write(info.FileID)
	hash := h.Sum(nil)
	
	encrypted := rc4Encrypt(key, hash)
	
	for i := 1; i <= 19; i++ {
		newKey := make([]byte, len(key))
		for j := range key {
			newKey[j] = key[j] ^ byte(i)
		}
		encrypted = rc4Encrypt(newKey, encrypted)
	}
	
	if len(info.UserHash) >= 16 {
		return bytes.Equal(encrypted[:16], info.UserHash[:16])
	}
	
	return false
}

func padPassword(password []byte) []byte {
	result := make([]byte, 32)
	n := copy(result, password)
	if n < 32 {
		copy(result[n:], pdfPadding[:32-n])
	}
	return result
}

func rc4Encrypt(key, data []byte) []byte {
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}
	
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}
	
	result := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		result[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}
	
	return result
}
