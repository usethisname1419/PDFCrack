# LTH PDF Cracker Makefile

VERSION := 1.0.0
BINARY := pdfcrack
OUTPUT_DIR := dist

GO := go
GOFLAGS := 
LDFLAGS := -ldflags="-s -w"
GPU_TAGS := -tags opencl

.PHONY: all build build-gpu clean test deps help

all: build

deps:
	$(GO) mod tidy
	$(GO) mod download

build: deps
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(OUTPUT_DIR)/$(BINARY) ./cmd/pdfcrack

build-gpu: deps
	CGO_ENABLED=1 $(GO) build $(GPU_TAGS) $(GOFLAGS) -o $(OUTPUT_DIR)/$(BINARY)-gpu ./cmd/pdfcrack

release: deps
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY) ./cmd/pdfcrack

release-gpu: deps
	CGO_ENABLED=1 $(GO) build $(GPU_TAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY)-gpu ./cmd/pdfcrack

# Cross-compilation (CPU only)
build-all: deps
	@mkdir -p $(OUTPUT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-windows-amd64.exe ./cmd/pdfcrack
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-windows-arm64.exe ./cmd/pdfcrack
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-linux-amd64 ./cmd/pdfcrack
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-linux-arm64 ./cmd/pdfcrack
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-darwin-amd64 ./cmd/pdfcrack
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/$(BINARY)-darwin-arm64 ./cmd/pdfcrack

test:
	$(GO) test -v ./...

benchmark:
	$(GO) test -bench=. -benchmem ./...

clean:
	rm -rf $(OUTPUT_DIR)
	$(GO) clean

help:
	@echo "LTH PDF Cracker Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build       - Build CPU-only binary"
	@echo "  build-gpu   - Build with GPU support (requires OpenCL)"
	@echo "  release     - Build optimized CPU binary"
	@echo "  release-gpu - Build optimized GPU binary"
	@echo "  build-all   - Cross-compile for all platforms"
	@echo "  test        - Run tests"
	@echo "  benchmark   - Run benchmarks"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Download dependencies"
