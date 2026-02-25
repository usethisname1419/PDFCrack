#!/bin/bash
# LTH PDF Cracker - Build Script for Linux/macOS
# Usage: ./build.sh [--gpu] [--release] [--all]

set -e

VERSION="1.0.0"
OUTPUT_DIR="dist"

GPU=false
RELEASE=false
ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --gpu|-g) GPU=true; shift ;;
        --release|-r) RELEASE=true; shift ;;
        --all|-a) ALL=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

build_binary() {
    local os=$1
    local arch=$2
    local with_gpu=$3

    export GOOS=$os
    export GOARCH=$arch
    
    if [ "$with_gpu" = true ]; then
        export CGO_ENABLED=1
    else
        export CGO_ENABLED=0
    fi

    local ext=""
    [ "$os" = "windows" ] && ext=".exe"
    
    local gpu_suffix=""
    [ "$with_gpu" = true ] && gpu_suffix="-gpu"
    
    local output_name="pdfcrack-${os}-${arch}${gpu_suffix}${ext}"
    local output_path="${OUTPUT_DIR}/${output_name}"

    local tags=""
    [ "$with_gpu" = true ] && tags="-tags opencl"
    
    local ldflags=""
    [ "$RELEASE" = true ] && ldflags="-ldflags=-s -w"

    echo -e "\033[36mBuilding $output_name...\033[0m"

    if go build $tags $ldflags -o "$output_path" ./cmd/pdfcrack; then
        echo -e "\033[32m  -> $output_path\033[0m"
    else
        echo -e "\033[31m  -> Build failed!\033[0m"
        return 1
    fi
}

echo ""
echo -e "\033[33mLTH PDF Cracker Build Script v$VERSION\033[0m"
echo -e "\033[33m=======================================\033[0m"
echo ""

echo -e "\033[36mDownloading dependencies...\033[0m"
go mod tidy

if [ "$ALL" = true ]; then
    # Build all platforms
    platforms=(
        "windows:amd64"
        "windows:arm64"
        "linux:amd64"
        "linux:arm64"
        "darwin:amd64"
        "darwin:arm64"
    )

    for p in "${platforms[@]}"; do
        IFS=":" read -r os arch <<< "$p"
        build_binary "$os" "$arch" false
    done

    if [ "$GPU" = true ]; then
        echo ""
        echo -e "\033[33mGPU builds require native compilation (CGO)\033[0m"
        
        # Detect current OS
        case "$(uname -s)" in
            Linux*) build_binary "linux" "amd64" true ;;
            Darwin*) build_binary "darwin" "amd64" true ;;
        esac
    fi
else
    # Build for current platform
    case "$(uname -s)" in
        Linux*) os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *) os="linux" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) arch="amd64" ;;
    esac

    build_binary "$os" "$arch" "$GPU"
fi

echo ""
echo -e "\033[32mBuild complete!\033[0m"
echo -e "\033[36mOutput directory: $OUTPUT_DIR\033[0m"
