// +build !opencl

package gpu

import (
	"errors"

	"github.com/lth/pdfcrack/internal/pdf"
)

var ErrGPUNotCompiled = errors.New("GPU support not compiled - rebuild with -tags opencl")

type GPUCracker struct {
	available bool
}

func NewGPUCracker(encInfo *pdf.EncryptionInfo, batchSize int) (*GPUCracker, error) {
	return nil, ErrGPUNotCompiled
}

func (gc *GPUCracker) Available() bool {
	return false
}

func (gc *GPUCracker) CrackBatch(passwords []string) (string, bool) {
	return "", false
}

func (gc *GPUCracker) Close() {}

func (gc *GPUCracker) DeviceInfo() string {
	return "GPU support not compiled"
}
