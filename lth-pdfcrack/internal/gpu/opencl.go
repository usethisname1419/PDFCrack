// +build opencl

package gpu

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lOpenCL
#include <CL/cl.h>
#include <stdlib.h>
#include <string.h>

// OpenCL kernel for MD5 + RC4 password verification (PDF R2-R4)
const char* kernelSource =
"__constant uchar padding[32] = {                                          \n"
"    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,                       \n"
"    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,                       \n"
"    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,                       \n"
"    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A                        \n"
"};                                                                        \n"
"                                                                          \n"
"#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))                           \n"
"#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))                           \n"
"#define H(x, y, z) ((x) ^ (y) ^ (z))                                      \n"
"#define I(x, y, z) ((y) ^ ((x) | (~z)))                                   \n"
"#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))              \n"
"                                                                          \n"
"#define FF(a, b, c, d, x, s, ac) {                                        \n"
"    (a) += F((b), (c), (d)) + (x) + (uint)(ac);                           \n"
"    (a) = ROTATE_LEFT((a), (s));                                          \n"
"    (a) += (b);                                                           \n"
"}                                                                         \n"
"#define GG(a, b, c, d, x, s, ac) {                                        \n"
"    (a) += G((b), (c), (d)) + (x) + (uint)(ac);                           \n"
"    (a) = ROTATE_LEFT((a), (s));                                          \n"
"    (a) += (b);                                                           \n"
"}                                                                         \n"
"#define HH(a, b, c, d, x, s, ac) {                                        \n"
"    (a) += H((b), (c), (d)) + (x) + (uint)(ac);                           \n"
"    (a) = ROTATE_LEFT((a), (s));                                          \n"
"    (a) += (b);                                                           \n"
"}                                                                         \n"
"#define II(a, b, c, d, x, s, ac) {                                        \n"
"    (a) += I((b), (c), (d)) + (x) + (uint)(ac);                           \n"
"    (a) = ROTATE_LEFT((a), (s));                                          \n"
"    (a) += (b);                                                           \n"
"}                                                                         \n"
"                                                                          \n"
"void md5_transform(__private uint state[4], __private uchar block[64]) {  \n"
"    uint a = state[0], b = state[1], c = state[2], d = state[3];          \n"
"    uint x[16];                                                           \n"
"    for (int i = 0; i < 16; i++) {                                        \n"
"        x[i] = ((uint)block[i*4]) | ((uint)block[i*4+1] << 8) |           \n"
"               ((uint)block[i*4+2] << 16) | ((uint)block[i*4+3] << 24);   \n"
"    }                                                                     \n"
"    FF(a, b, c, d, x[ 0],  7, 0xd76aa478);                                \n"
"    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);                                \n"
"    FF(c, d, a, b, x[ 2], 17, 0x242070db);                                \n"
"    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);                                \n"
"    FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);                                \n"
"    FF(d, a, b, c, x[ 5], 12, 0x4787c62a);                                \n"
"    FF(c, d, a, b, x[ 6], 17, 0xa8304613);                                \n"
"    FF(b, c, d, a, x[ 7], 22, 0xfd469501);                                \n"
"    FF(a, b, c, d, x[ 8],  7, 0x698098d8);                                \n"
"    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);                                \n"
"    FF(c, d, a, b, x[10], 17, 0xffff5bb1);                                \n"
"    FF(b, c, d, a, x[11], 22, 0x895cd7be);                                \n"
"    FF(a, b, c, d, x[12],  7, 0x6b901122);                                \n"
"    FF(d, a, b, c, x[13], 12, 0xfd987193);                                \n"
"    FF(c, d, a, b, x[14], 17, 0xa679438e);                                \n"
"    FF(b, c, d, a, x[15], 22, 0x49b40821);                                \n"
"    GG(a, b, c, d, x[ 1],  5, 0xf61e2562);                                \n"
"    GG(d, a, b, c, x[ 6],  9, 0xc040b340);                                \n"
"    GG(c, d, a, b, x[11], 14, 0x265e5a51);                                \n"
"    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);                                \n"
"    GG(a, b, c, d, x[ 5],  5, 0xd62f105d);                                \n"
"    GG(d, a, b, c, x[10],  9, 0x02441453);                                \n"
"    GG(c, d, a, b, x[15], 14, 0xd8a1e681);                                \n"
"    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);                                \n"
"    GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);                                \n"
"    GG(d, a, b, c, x[14],  9, 0xc33707d6);                                \n"
"    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);                                \n"
"    GG(b, c, d, a, x[ 8], 20, 0x455a14ed);                                \n"
"    GG(a, b, c, d, x[13],  5, 0xa9e3e905);                                \n"
"    GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);                                \n"
"    GG(c, d, a, b, x[ 7], 14, 0x676f02d9);                                \n"
"    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);                                \n"
"    HH(a, b, c, d, x[ 5],  4, 0xfffa3942);                                \n"
"    HH(d, a, b, c, x[ 8], 11, 0x8771f681);                                \n"
"    HH(c, d, a, b, x[11], 16, 0x6d9d6122);                                \n"
"    HH(b, c, d, a, x[14], 23, 0xfde5380c);                                \n"
"    HH(a, b, c, d, x[ 1],  4, 0xa4beea44);                                \n"
"    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);                                \n"
"    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);                                \n"
"    HH(b, c, d, a, x[10], 23, 0xbebfbc70);                                \n"
"    HH(a, b, c, d, x[13],  4, 0x289b7ec6);                                \n"
"    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);                                \n"
"    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);                                \n"
"    HH(b, c, d, a, x[ 6], 23, 0x04881d05);                                \n"
"    HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);                                \n"
"    HH(d, a, b, c, x[12], 11, 0xe6db99e5);                                \n"
"    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);                                \n"
"    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);                                \n"
"    II(a, b, c, d, x[ 0],  6, 0xf4292244);                                \n"
"    II(d, a, b, c, x[ 7], 10, 0x432aff97);                                \n"
"    II(c, d, a, b, x[14], 15, 0xab9423a7);                                \n"
"    II(b, c, d, a, x[ 5], 21, 0xfc93a039);                                \n"
"    II(a, b, c, d, x[12],  6, 0x655b59c3);                                \n"
"    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);                                \n"
"    II(c, d, a, b, x[10], 15, 0xffeff47d);                                \n"
"    II(b, c, d, a, x[ 1], 21, 0x85845dd1);                                \n"
"    II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);                                \n"
"    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);                                \n"
"    II(c, d, a, b, x[ 6], 15, 0xa3014314);                                \n"
"    II(b, c, d, a, x[13], 21, 0x4e0811a1);                                \n"
"    II(a, b, c, d, x[ 4],  6, 0xf7537e82);                                \n"
"    II(d, a, b, c, x[11], 10, 0xbd3af235);                                \n"
"    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);                                \n"
"    II(b, c, d, a, x[ 9], 21, 0xeb86d391);                                \n"
"    state[0] += a; state[1] += b; state[2] += c; state[3] += d;          \n"
"}                                                                         \n"
"                                                                          \n"
"void rc4_crypt(__private uchar *key, int keylen,                          \n"
"               __private uchar *data, int datalen,                        \n"
"               __private uchar *out) {                                    \n"
"    uchar s[256];                                                         \n"
"    for (int i = 0; i < 256; i++) s[i] = i;                               \n"
"    int j = 0;                                                            \n"
"    for (int i = 0; i < 256; i++) {                                       \n"
"        j = (j + s[i] + key[i % keylen]) & 0xff;                          \n"
"        uchar t = s[i]; s[i] = s[j]; s[j] = t;                            \n"
"    }                                                                     \n"
"    int i = 0; j = 0;                                                     \n"
"    for (int k = 0; k < datalen; k++) {                                   \n"
"        i = (i + 1) & 0xff;                                               \n"
"        j = (j + s[i]) & 0xff;                                            \n"
"        uchar t = s[i]; s[i] = s[j]; s[j] = t;                            \n"
"        out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];                       \n"
"    }                                                                     \n"
"}                                                                         \n"
"                                                                          \n"
"__kernel void crack_pdf(                                                  \n"
"    __global uchar *passwords,                                            \n"
"    __global int *password_lengths,                                       \n"
"    int max_password_len,                                                 \n"
"    __global uchar *owner_hash,                                           \n"
"    __global uchar *user_hash,                                            \n"
"    __global uchar *file_id,                                              \n"
"    int file_id_len,                                                      \n"
"    int permissions,                                                      \n"
"    int revision,                                                         \n"
"    int key_length,                                                       \n"
"    __global int *result_index,                                           \n"
"    __global int *found)                                                  \n"
"{                                                                         \n"
"    int gid = get_global_id(0);                                           \n"
"    if (*found) return;                                                   \n"
"                                                                          \n"
"    __global uchar *pwd = passwords + gid * max_password_len;             \n"
"    int pwd_len = password_lengths[gid];                                  \n"
"                                                                          \n"
"    uchar padded[32];                                                     \n"
"    for (int i = 0; i < 32; i++) {                                        \n"
"        padded[i] = (i < pwd_len) ? pwd[i] : padding[i - pwd_len];        \n"
"    }                                                                     \n"
"                                                                          \n"
"    // MD5 of padded password + owner + permissions + file_id             \n"
"    uchar md5_input[128];                                                 \n"
"    int offset = 0;                                                       \n"
"    for (int i = 0; i < 32; i++) md5_input[offset++] = padded[i];         \n"
"    for (int i = 0; i < 32; i++) md5_input[offset++] = owner_hash[i];     \n"
"    md5_input[offset++] = permissions & 0xff;                             \n"
"    md5_input[offset++] = (permissions >> 8) & 0xff;                      \n"
"    md5_input[offset++] = (permissions >> 16) & 0xff;                     \n"
"    md5_input[offset++] = (permissions >> 24) & 0xff;                     \n"
"    for (int i = 0; i < file_id_len; i++) md5_input[offset++] = file_id[i];\n"
"                                                                          \n"
"    // Compute MD5 (simplified - actual impl needs proper padding)        \n"
"    uint state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};     \n"
"    uchar block[64];                                                      \n"
"    for (int i = 0; i < 64; i++) block[i] = (i < offset) ? md5_input[i] : 0;\n"
"    block[offset] = 0x80;                                                 \n"
"    block[56] = (offset * 8) & 0xff;                                      \n"
"    block[57] = ((offset * 8) >> 8) & 0xff;                               \n"
"    md5_transform(state, block);                                          \n"
"                                                                          \n"
"    uchar key[16];                                                        \n"
"    for (int i = 0; i < 4; i++) {                                         \n"
"        key[i*4+0] = state[i] & 0xff;                                     \n"
"        key[i*4+1] = (state[i] >> 8) & 0xff;                              \n"
"        key[i*4+2] = (state[i] >> 16) & 0xff;                             \n"
"        key[i*4+3] = (state[i] >> 24) & 0xff;                             \n"
"    }                                                                     \n"
"                                                                          \n"
"    int klen = key_length / 8;                                            \n"
"    if (klen > 16) klen = 16;                                             \n"
"    if (klen < 5) klen = 5;                                               \n"
"                                                                          \n"
"    if (revision >= 3) {                                                  \n"
"        for (int iter = 0; iter < 50; iter++) {                           \n"
"            for (int i = 0; i < 64; i++) block[i] = (i < klen) ? key[i] : 0;\n"
"            block[klen] = 0x80;                                           \n"
"            for (int i = klen+1; i < 56; i++) block[i] = 0;               \n"
"            block[56] = (klen * 8) & 0xff;                                \n"
"            block[57] = ((klen * 8) >> 8) & 0xff;                         \n"
"            for (int i = 58; i < 64; i++) block[i] = 0;                   \n"
"            state[0] = 0x67452301; state[1] = 0xefcdab89;                 \n"
"            state[2] = 0x98badcfe; state[3] = 0x10325476;                 \n"
"            md5_transform(state, block);                                  \n"
"            for (int i = 0; i < 4; i++) {                                 \n"
"                key[i*4+0] = state[i] & 0xff;                             \n"
"                key[i*4+1] = (state[i] >> 8) & 0xff;                      \n"
"                key[i*4+2] = (state[i] >> 16) & 0xff;                     \n"
"                key[i*4+3] = (state[i] >> 24) & 0xff;                     \n"
"            }                                                             \n"
"        }                                                                 \n"
"    }                                                                     \n"
"                                                                          \n"
"    // Verify user password                                               \n"
"    uchar test[32], encrypted[32];                                        \n"
"    if (revision == 2) {                                                  \n"
"        for (int i = 0; i < 32; i++) test[i] = padding[i];                \n"
"        rc4_crypt(key, klen, test, 32, encrypted);                        \n"
"        int match = 1;                                                    \n"
"        for (int i = 0; i < 32; i++) {                                    \n"
"            if (encrypted[i] != user_hash[i]) { match = 0; break; }       \n"
"        }                                                                 \n"
"        if (match) {                                                      \n"
"            atomic_xchg(found, 1);                                        \n"
"            atomic_xchg(result_index, gid);                               \n"
"        }                                                                 \n"
"    } else {                                                              \n"
"        // R3/R4: MD5(padding + file_id) then RC4 with key iterations     \n"
"        for (int i = 0; i < 32; i++) md5_input[i] = padding[i];           \n"
"        for (int i = 0; i < file_id_len; i++) md5_input[32+i] = file_id[i];\n"
"        int total = 32 + file_id_len;                                     \n"
"        for (int i = 0; i < 64; i++) block[i] = (i < total) ? md5_input[i] : 0;\n"
"        block[total] = 0x80;                                              \n"
"        block[56] = (total * 8) & 0xff;                                   \n"
"        block[57] = ((total * 8) >> 8) & 0xff;                            \n"
"        state[0] = 0x67452301; state[1] = 0xefcdab89;                     \n"
"        state[2] = 0x98badcfe; state[3] = 0x10325476;                     \n"
"        md5_transform(state, block);                                      \n"
"        for (int i = 0; i < 16; i++) {                                    \n"
"            test[i] = (state[i/4] >> ((i%4)*8)) & 0xff;                   \n"
"        }                                                                 \n"
"        rc4_crypt(key, klen, test, 16, encrypted);                        \n"
"        for (int iter = 1; iter <= 19; iter++) {                          \n"
"            uchar iterkey[16];                                            \n"
"            for (int i = 0; i < klen; i++) iterkey[i] = key[i] ^ iter;    \n"
"            uchar temp[16];                                               \n"
"            rc4_crypt(iterkey, klen, encrypted, 16, temp);                \n"
"            for (int i = 0; i < 16; i++) encrypted[i] = temp[i];          \n"
"        }                                                                 \n"
"        int match = 1;                                                    \n"
"        for (int i = 0; i < 16; i++) {                                    \n"
"            if (encrypted[i] != user_hash[i]) { match = 0; break; }       \n"
"        }                                                                 \n"
"        if (match) {                                                      \n"
"            atomic_xchg(found, 1);                                        \n"
"            atomic_xchg(result_index, gid);                               \n"
"        }                                                                 \n"
"    }                                                                     \n"
"}                                                                         \n";

*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/lth/pdfcrack/internal/pdf"
)

var (
	ErrNoGPU         = errors.New("no OpenCL-capable GPU found")
	ErrGPUInit       = errors.New("failed to initialize GPU")
	ErrKernelCompile = errors.New("failed to compile OpenCL kernel")
)

type GPUCracker struct {
	encInfo    *pdf.EncryptionInfo
	platform   C.cl_platform_id
	device     C.cl_device_id
	context    C.cl_context
	queue      C.cl_command_queue
	program    C.cl_program
	kernel     C.cl_kernel
	batchSize  int
	available  bool
}

func NewGPUCracker(encInfo *pdf.EncryptionInfo, batchSize int) (*GPUCracker, error) {
	gc := &GPUCracker{
		encInfo:   encInfo,
		batchSize: batchSize,
	}

	var numPlatforms C.cl_uint
	err := C.clGetPlatformIDs(0, nil, &numPlatforms)
	if err != C.CL_SUCCESS || numPlatforms == 0 {
		return nil, ErrNoGPU
	}

	platforms := make([]C.cl_platform_id, numPlatforms)
	C.clGetPlatformIDs(numPlatforms, &platforms[0], nil)

	var foundDevice bool
	for _, platform := range platforms {
		var numDevices C.cl_uint
		err := C.clGetDeviceIDs(platform, C.CL_DEVICE_TYPE_GPU, 0, nil, &numDevices)
		if err == C.CL_SUCCESS && numDevices > 0 {
			devices := make([]C.cl_device_id, numDevices)
			C.clGetDeviceIDs(platform, C.CL_DEVICE_TYPE_GPU, numDevices, &devices[0], nil)
			gc.platform = platform
			gc.device = devices[0]
			foundDevice = true
			break
		}
	}

	if !foundDevice {
		return nil, ErrNoGPU
	}

	var clErr C.cl_int
	gc.context = C.clCreateContext(nil, 1, &gc.device, nil, nil, &clErr)
	if clErr != C.CL_SUCCESS {
		return nil, ErrGPUInit
	}

	gc.queue = C.clCreateCommandQueue(gc.context, gc.device, 0, &clErr)
	if clErr != C.CL_SUCCESS {
		C.clReleaseContext(gc.context)
		return nil, ErrGPUInit
	}

	kernelSrc := C.kernelSource
	gc.program = C.clCreateProgramWithSource(gc.context, 1, &kernelSrc, nil, &clErr)
	if clErr != C.CL_SUCCESS {
		gc.cleanup()
		return nil, ErrKernelCompile
	}

	err = C.clBuildProgram(gc.program, 1, &gc.device, nil, nil, nil)
	if err != C.CL_SUCCESS {
		gc.cleanup()
		return nil, ErrKernelCompile
	}

	kernelName := C.CString("crack_pdf")
	defer C.free(unsafe.Pointer(kernelName))
	gc.kernel = C.clCreateKernel(gc.program, kernelName, &clErr)
	if clErr != C.CL_SUCCESS {
		gc.cleanup()
		return nil, ErrKernelCompile
	}

	gc.available = true
	return gc, nil
}

func (gc *GPUCracker) Available() bool {
	return gc.available
}

func (gc *GPUCracker) CrackBatch(passwords []string) (string, bool) {
	if !gc.available || len(passwords) == 0 {
		return "", false
	}

	maxLen := 32
	pwdData := make([]byte, len(passwords)*maxLen)
	pwdLens := make([]int32, len(passwords))

	for i, pwd := range passwords {
		pwdBytes := []byte(pwd)
		if len(pwdBytes) > maxLen {
			pwdBytes = pwdBytes[:maxLen]
		}
		copy(pwdData[i*maxLen:], pwdBytes)
		pwdLens[i] = int32(len(pwdBytes))
	}

	var clErr C.cl_int

	pwdBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(pwdData)), unsafe.Pointer(&pwdData[0]), &clErr)
	defer C.clReleaseMemObject(pwdBuf)

	lenBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(pwdLens)*4), unsafe.Pointer(&pwdLens[0]), &clErr)
	defer C.clReleaseMemObject(lenBuf)

	ownerHash := gc.encInfo.OwnerHash
	if len(ownerHash) < 32 {
		ownerHash = append(ownerHash, make([]byte, 32-len(ownerHash))...)
	}
	ownerBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		32, unsafe.Pointer(&ownerHash[0]), &clErr)
	defer C.clReleaseMemObject(ownerBuf)

	userHash := gc.encInfo.UserHash
	if len(userHash) < 32 {
		userHash = append(userHash, make([]byte, 32-len(userHash))...)
	}
	userBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		32, unsafe.Pointer(&userHash[0]), &clErr)
	defer C.clReleaseMemObject(userBuf)

	fileID := gc.encInfo.FileID
	if len(fileID) == 0 {
		fileID = make([]byte, 16)
	}
	fileIDBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR,
		C.size_t(len(fileID)), unsafe.Pointer(&fileID[0]), &clErr)
	defer C.clReleaseMemObject(fileIDBuf)

	resultIndex := int32(-1)
	found := int32(0)
	resultBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_WRITE|C.CL_MEM_COPY_HOST_PTR,
		4, unsafe.Pointer(&resultIndex), &clErr)
	defer C.clReleaseMemObject(resultBuf)
	foundBuf := C.clCreateBuffer(gc.context, C.CL_MEM_READ_WRITE|C.CL_MEM_COPY_HOST_PTR,
		4, unsafe.Pointer(&found), &clErr)
	defer C.clReleaseMemObject(foundBuf)

	maxLenArg := C.int(maxLen)
	fileIDLen := C.int(len(fileID))
	permissions := C.int(gc.encInfo.Permissions)
	revision := C.int(gc.encInfo.Revision)
	keyLength := C.int(gc.encInfo.Length)

	C.clSetKernelArg(gc.kernel, 0, C.size_t(unsafe.Sizeof(pwdBuf)), unsafe.Pointer(&pwdBuf))
	C.clSetKernelArg(gc.kernel, 1, C.size_t(unsafe.Sizeof(lenBuf)), unsafe.Pointer(&lenBuf))
	C.clSetKernelArg(gc.kernel, 2, C.size_t(unsafe.Sizeof(maxLenArg)), unsafe.Pointer(&maxLenArg))
	C.clSetKernelArg(gc.kernel, 3, C.size_t(unsafe.Sizeof(ownerBuf)), unsafe.Pointer(&ownerBuf))
	C.clSetKernelArg(gc.kernel, 4, C.size_t(unsafe.Sizeof(userBuf)), unsafe.Pointer(&userBuf))
	C.clSetKernelArg(gc.kernel, 5, C.size_t(unsafe.Sizeof(fileIDBuf)), unsafe.Pointer(&fileIDBuf))
	C.clSetKernelArg(gc.kernel, 6, C.size_t(unsafe.Sizeof(fileIDLen)), unsafe.Pointer(&fileIDLen))
	C.clSetKernelArg(gc.kernel, 7, C.size_t(unsafe.Sizeof(permissions)), unsafe.Pointer(&permissions))
	C.clSetKernelArg(gc.kernel, 8, C.size_t(unsafe.Sizeof(revision)), unsafe.Pointer(&revision))
	C.clSetKernelArg(gc.kernel, 9, C.size_t(unsafe.Sizeof(keyLength)), unsafe.Pointer(&keyLength))
	C.clSetKernelArg(gc.kernel, 10, C.size_t(unsafe.Sizeof(resultBuf)), unsafe.Pointer(&resultBuf))
	C.clSetKernelArg(gc.kernel, 11, C.size_t(unsafe.Sizeof(foundBuf)), unsafe.Pointer(&foundBuf))

	globalSize := C.size_t(len(passwords))
	C.clEnqueueNDRangeKernel(gc.queue, gc.kernel, 1, nil, &globalSize, nil, 0, nil, nil)
	C.clFinish(gc.queue)

	C.clEnqueueReadBuffer(gc.queue, foundBuf, C.CL_TRUE, 0, 4, unsafe.Pointer(&found), 0, nil, nil)
	C.clEnqueueReadBuffer(gc.queue, resultBuf, C.CL_TRUE, 0, 4, unsafe.Pointer(&resultIndex), 0, nil, nil)

	if found != 0 && resultIndex >= 0 && int(resultIndex) < len(passwords) {
		return passwords[resultIndex], true
	}

	return "", false
}

func (gc *GPUCracker) cleanup() {
	if gc.kernel != nil {
		C.clReleaseKernel(gc.kernel)
	}
	if gc.program != nil {
		C.clReleaseProgram(gc.program)
	}
	if gc.queue != nil {
		C.clReleaseCommandQueue(gc.queue)
	}
	if gc.context != nil {
		C.clReleaseContext(gc.context)
	}
}

func (gc *GPUCracker) Close() {
	gc.cleanup()
	gc.available = false
}

func (gc *GPUCracker) DeviceInfo() string {
	if !gc.available {
		return "No GPU available"
	}

	name := make([]byte, 256)
	C.clGetDeviceInfo(gc.device, C.CL_DEVICE_NAME, 256, unsafe.Pointer(&name[0]), nil)

	var maxUnits C.cl_uint
	C.clGetDeviceInfo(gc.device, C.CL_DEVICE_MAX_COMPUTE_UNITS, C.size_t(unsafe.Sizeof(maxUnits)), unsafe.Pointer(&maxUnits), nil)

	return fmt.Sprintf("%s (%d compute units)", string(name), maxUnits)
}
