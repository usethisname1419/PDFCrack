package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	algo := "RC4"
	if e.IsAES {
		algo = "AES"
	}
	return fmt.Sprintf("PDF %s, V%d R%d, %d-bit %s", 
		e.PDFVersion, e.Version, e.Revision, e.Length, algo)
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

	encryptDict, err := findEncryptDict(data)
	if err != nil {
		return nil, err
	}

	if err := parseEncryptDict(data, encryptDict, info); err != nil {
		return nil, err
	}

	if err := parseFileID(data, info); err != nil {
		return nil, err
	}

	return info, nil
}

func findEncryptDict(data []byte) ([]byte, error) {
	encryptRefMatch := regexp.MustCompile(`/Encrypt\s+(\d+)\s+(\d+)\s+R`).FindSubmatch(data)
	if encryptRefMatch != nil {
		objNum := string(encryptRefMatch[1])
		objPattern := regexp.MustCompile(objNum + `\s+\d+\s+obj\s*<<([\s\S]*?)>>\s*endobj`)
		objMatch := objPattern.FindSubmatch(data)
		if objMatch != nil {
			return objMatch[1], nil
		}
		
		objPattern2 := regexp.MustCompile(objNum + `\s+\d+\s+obj\s*<<([\s\S]*?)>>`)
		objMatch2 := objPattern2.FindSubmatch(data)
		if objMatch2 != nil {
			return objMatch2[1], nil
		}
	}

	inlineMatch := regexp.MustCompile(`/Encrypt\s*<<([\s\S]*?)>>`).FindSubmatch(data)
	if inlineMatch != nil {
		return inlineMatch[1], nil
	}

	return nil, ErrNotEncrypted
}

func parseEncryptDict(fullData []byte, encryptDict []byte, info *EncryptionInfo) error {
	vMatch := regexp.MustCompile(`/V\s+(\d+)`).FindSubmatch(encryptDict)
	if vMatch != nil {
		info.Version, _ = strconv.Atoi(string(vMatch[1]))
	}

	rMatch := regexp.MustCompile(`/R\s+(\d+)`).FindSubmatch(encryptDict)
	if rMatch != nil {
		info.Revision, _ = strconv.Atoi(string(rMatch[1]))
	}

	lengthMatch := regexp.MustCompile(`/Length\s+(\d+)`).FindSubmatch(encryptDict)
	if lengthMatch != nil {
		length, _ := strconv.Atoi(string(lengthMatch[1]))
		if length >= 40 && length <= 256 {
			info.Length = length
		} else if length > 0 && length <= 32 {
			info.Length = length * 8
		} else {
			info.Length = 128
		}
	} else {
		if info.Version >= 4 {
			info.Length = 128
		} else if info.Version >= 2 {
			info.Length = 128
		} else {
			info.Length = 40
		}
	}

	pMatch := regexp.MustCompile(`/P\s+(-?\d+)`).FindSubmatch(encryptDict)
	if pMatch != nil {
		p, _ := strconv.ParseInt(string(pMatch[1]), 10, 32)
		info.Permissions = int32(p)
	}

	oMatch := regexp.MustCompile(`/O\s*[<(]([^>)]+)[>)]`).FindSubmatch(encryptDict)
	if oMatch != nil {
		info.OwnerHash = parseHexOrLiteral(oMatch[1])
	}

	uMatch := regexp.MustCompile(`/U\s*[<(]([^>)]+)[>)]`).FindSubmatch(encryptDict)
	if uMatch != nil {
		info.UserHash = parseHexOrLiteral(uMatch[1])
	}

	info.IsAES = false
	
	cfmMatch := regexp.MustCompile(`/CFM\s*/AESV2`).FindSubmatch(encryptDict)
	if cfmMatch != nil {
		info.IsAES = true
	}
	
	cfmMatch = regexp.MustCompile(`/CFM\s*/AESV2`).FindSubmatch(fullData)
	if cfmMatch != nil {
		info.IsAES = true
	}
	
	cfmMatch3 := regexp.MustCompile(`/CFM\s*/AESV3`).FindSubmatch(fullData)
	if cfmMatch3 != nil {
		info.IsAES = true
	}

	stmFMatch := regexp.MustCompile(`/StmF\s*/StdCF`).FindSubmatch(encryptDict)
	if stmFMatch != nil {
		stdcfMatch := regexp.MustCompile(`/StdCF\s*<<[^>]*?/CFM\s*/AESV2`).FindSubmatch(fullData)
		if stdcfMatch != nil {
			info.IsAES = true
		}
	}

	encryptMetaMatch := regexp.MustCompile(`/EncryptMetadata\s+(true|false)`).FindSubmatch(encryptDict)
	if encryptMetaMatch != nil {
		info.EncryptMeta = string(encryptMetaMatch[1]) == "true"
	} else {
		info.EncryptMeta = true
	}

	if info.Version == 0 {
		info.Version = 1
	}
	if info.Revision == 0 {
		info.Revision = 2
	}

	return nil
}

func parseFileID(data []byte, info *EncryptionInfo) error {
	idMatch := regexp.MustCompile(`/ID\s*\[\s*<([0-9A-Fa-f]+)>`).FindSubmatch(data)
	if idMatch != nil {
		info.FileID = parseHexOrLiteral(idMatch[1])
		return nil
	}
	
	idMatch = regexp.MustCompile(`/ID\s*\[\s*\(([^)]+)\)`).FindSubmatch(data)
	if idMatch != nil {
		info.FileID = unescapePDFString(idMatch[1])
	}
	return nil
}

func parseHexOrLiteral(data []byte) []byte {
	s := string(data)
	s = strings.TrimSpace(s)
	
	isHex := true
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	
	if isHex && len(s) > 0 {
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
	
	return unescapePDFString([]byte(s))
}

func unescapePDFString(data []byte) []byte {
	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == '\\' && i+1 < len(data) {
			switch data[i+1] {
			case 'n':
				result = append(result, '\n')
				i += 2
			case 'r':
				result = append(result, '\r')
				i += 2
			case 't':
				result = append(result, '\t')
				i += 2
			case '\\':
				result = append(result, '\\')
				i += 2
			case '(':
				result = append(result, '(')
				i += 2
			case ')':
				result = append(result, ')')
				i += 2
			default:
				if data[i+1] >= '0' && data[i+1] <= '7' {
					octal := 0
					j := i + 1
					for k := 0; k < 3 && j < len(data) && data[j] >= '0' && data[j] <= '7'; k++ {
						octal = octal*8 + int(data[j]-'0')
						j++
					}
					result = append(result, byte(octal))
					i = j
				} else {
					result = append(result, data[i+1])
					i += 2
				}
			}
		} else {
			result = append(result, data[i])
			i++
		}
	}
	return result
}

var pdfPadding = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

func (info *EncryptionInfo) CheckPassword(password string) bool {
	if info.Revision >= 5 {
		return false
	}
	
	key := info.computeEncryptionKey(password)
	if key == nil {
		return false
	}
	
	if info.IsAES {
		return info.verifyUserPasswordAES(key)
	}
	return info.verifyUserPasswordRC4(key)
}

func (info *EncryptionInfo) computeEncryptionKey(password string) []byte {
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
	
	return key[:keyLen]
}

func (info *EncryptionInfo) verifyUserPasswordRC4(key []byte) bool {
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

func (info *EncryptionInfo) verifyUserPasswordAES(key []byte) bool {
	if len(info.UserHash) < 32 {
		return false
	}
	
	if len(key) != 16 {
		newKey := make([]byte, 16)
		copy(newKey, key)
		key = newKey
	}

	iv := info.UserHash[:16]
	encrypted := info.UserHash[16:32]
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	
	decrypted := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encrypted)
	
	h := md5.New()
	h.Write(pdfPadding)
	h.Write(info.FileID)
	expected := h.Sum(nil)
	
	return bytes.Equal(decrypted, expected)
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
