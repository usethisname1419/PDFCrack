# LTH PDF Password Cracker

A high-performance PDF password recovery tool written in Go with optional GPU acceleration.

## Features

- **Fast CPU-based cracking** with multi-threaded worker pool
- **Optional GPU acceleration** via OpenCL (up to 47x speedup)
- **Simultaneous attack modes** - run 1, 2, or all 3 modes at once:
  - `-W` Wordlist/dictionary attack
  - `-I` Incremental brute-force
  - `-R` Random password generation
- **PDF encryption support:** V1-V4, R2-R4 (PDF 1.1 - 1.7)
- **Cross-platform:** Windows, Linux, macOS
- **Real-time progress** for each attack mode

## Installation

### Pre-built Binaries

Download from the releases page.

### Build from Source

```bash
# Standard build (CPU only)
go build -o pdfcrack ./cmd/pdfcrack

# With GPU support (requires OpenCL SDK)
go build -tags opencl -o pdfcrack-gpu ./cmd/pdfcrack
```

### GPU Support Requirements

For GPU acceleration, you need:

**Windows:**
- NVIDIA: CUDA Toolkit with OpenCL support
- AMD: AMD APP SDK or ROCm
- Intel: Intel OpenCL Runtime

**Linux:**
```bash
# NVIDIA
sudo apt install nvidia-opencl-dev

# AMD
sudo apt install rocm-opencl-dev

# Intel
sudo apt install intel-opencl-icd
```

**macOS:**
- OpenCL is included with Xcode Command Line Tools

## Usage

### Basic Usage

```bash
# Single mode - Wordlist only
pdfcrack -f encrypted.pdf -W -w wordlist.txt

# Single mode - Incremental brute-force (4-6 digit PIN)
pdfcrack -f encrypted.pdf -I -c digits -m 4 -M 6

# Single mode - Random attack
pdfcrack -f encrypted.pdf -R -c alnum -m 1 -M 8

# Two modes - Wordlist + Incremental simultaneously
pdfcrack -f encrypted.pdf -W -I -w wordlist.txt -c alnum -m 1 -M 6

# All three modes at once
pdfcrack -f encrypted.pdf -W -I -R -w wordlist.txt -c alnum -m 1 -M 8

# With GPU acceleration (wordlist mode)
pdfcrack -f encrypted.pdf -W -w wordlist.txt --gpu
```

### Commands

```bash
# Show PDF encryption info
pdfcrack info -f encrypted.pdf

# Run performance benchmark
pdfcrack benchmark -f encrypted.pdf -t 8

# GPU benchmark
pdfcrack benchmark -f encrypted.pdf --gpu
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file` | PDF file to crack (required) | - |
| `-W, --use-wordlist` | Enable wordlist attack mode | false |
| `-I, --use-incremental` | Enable incremental attack mode | false |
| `-R, --use-random` | Enable random attack mode | false |
| `-w, --wordlist-file` | Wordlist file (required for -W) | - |
| `-c, --charset` | Character set (see below) | alnum |
| `-m, --min` | Minimum password length | 1 |
| `-M, --max` | Maximum password length | 8 |
| `-t, --workers` | CPU threads per attack mode | auto |
| `-g, --gpu` | Enable GPU acceleration | false |
| `-b, --batch` | GPU batch size | 10000 |
| `-v, --verbose` | Verbose output | false |

### Character Sets

| Name | Characters |
|------|------------|
| `lower` | a-z |
| `upper` | A-Z |
| `digits` | 0-9 |
| `alpha` | a-z, A-Z |
| `alnum` | a-z, A-Z, 0-9 |
| `all` | All printable + special |
| `special` | !@#$%^&*()_+-=[]{}... |
| Custom | Any string of characters |

## Performance

Typical performance on modern hardware:

| Mode | Hardware | Speed |
|------|----------|-------|
| CPU | 8-core Ryzen | ~500K p/s |
| CPU | 16-core Xeon | ~1M p/s |
| GPU | RTX 3080 | ~20M p/s |
| GPU | RTX 4090 | ~40M p/s |

## Examples

```bash
# Crack with rockyou wordlist
pdfcrack -f secret.pdf -W -w /usr/share/wordlists/rockyou.txt

# Brute-force 4-digit PIN
pdfcrack -f bank.pdf -I -c digits -m 4 -M 4

# Brute-force with custom charset
pdfcrack -f doc.pdf -I -c "abc123!@#" -m 1 -M 6

# Maximum coverage - all modes at once
pdfcrack -f doc.pdf -W -I -R -w rockyou.txt -c alnum -m 1 -M 8

# GPU-accelerated wordlist + incremental
pdfcrack -f doc.pdf -W -I -w huge_wordlist.txt --gpu -b 50000
```

## Supported PDF Versions

| PDF Version | Encryption | Supported |
|-------------|------------|-----------|
| 1.1-1.3 | V1 R2 (40-bit RC4) | ✓ |
| 1.4 | V2 R3 (128-bit RC4) | ✓ |
| 1.5-1.6 | V3 R4 (128-bit RC4/AES) | ✓ |
| 1.7 | V4 R4 (128-bit AES) | ✓ |
| 2.0 | V5 R5/R6 (256-bit AES) | Planned |

## Technical Details

The tool extracts the PDF encryption parameters (O/U hashes, permissions, file ID) and performs password verification using:

1. **Key derivation:** MD5-based key computation from password + PDF metadata
2. **Verification:** RC4/AES encryption of known plaintext and comparison with stored hash

GPU acceleration moves the computationally intensive MD5/RC4 operations to the GPU, allowing massive parallelization.

## License

Internal LTH tool. All rights reserved.

## Changelog

### v1.1.0
- Simultaneous multi-mode attacks (-W -I -R flags)
- Real-time per-mode progress display
- Improved CLI interface

### v1.0.0
- Initial release
- CPU multi-threaded cracking
- GPU acceleration via OpenCL
- Wordlist, incremental, and random attack modes
- PDF V1-V4 support
