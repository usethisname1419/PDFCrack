# LTH PDF Cracker - Build Script for Windows
# Usage: .\build.ps1 [-GPU] [-Release]

param(
    [switch]$GPU,
    [switch]$Release,
    [switch]$All
)

$ErrorActionPreference = "Stop"

$version = "1.0.0"
$outputDir = "dist"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Build-Binary {
    param(
        [string]$OS,
        [string]$Arch,
        [bool]$WithGPU
    )

    $env:GOOS = $OS
    $env:GOARCH = $Arch
    $env:CGO_ENABLED = if ($WithGPU) { "1" } else { "0" }

    $ext = if ($OS -eq "windows") { ".exe" } else { "" }
    $gpuSuffix = if ($WithGPU) { "-gpu" } else { "" }
    $outputName = "pdfcrack-${OS}-${Arch}${gpuSuffix}${ext}"
    $outputPath = Join-Path $outputDir $outputName

    $tags = if ($WithGPU) { "-tags opencl" } else { "" }
    $ldflags = if ($Release) { "-ldflags='-s -w'" } else { "" }

    Write-Host "Building $outputName..." -ForegroundColor Cyan

    $cmd = "go build $tags $ldflags -o `"$outputPath`" ./cmd/pdfcrack"
    Invoke-Expression $cmd

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  -> $outputPath" -ForegroundColor Green
    } else {
        Write-Host "  -> Build failed!" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "LTH PDF Cracker Build Script v$version" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host ""

# Get dependencies
Write-Host "Downloading dependencies..." -ForegroundColor Cyan
go mod tidy
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to download dependencies" -ForegroundColor Red
    exit 1
}

if ($All) {
    # Build all platforms
    $platforms = @(
        @{OS="windows"; Arch="amd64"},
        @{OS="windows"; Arch="arm64"},
        @{OS="linux"; Arch="amd64"},
        @{OS="linux"; Arch="arm64"},
        @{OS="darwin"; Arch="amd64"},
        @{OS="darwin"; Arch="arm64"}
    )

    foreach ($p in $platforms) {
        Build-Binary -OS $p.OS -Arch $p.Arch -WithGPU $false
    }

    if ($GPU) {
        Write-Host ""
        Write-Host "GPU builds require native compilation (CGO)" -ForegroundColor Yellow
        Build-Binary -OS "windows" -Arch "amd64" -WithGPU $true
    }
} else {
    # Build for current platform only
    Build-Binary -OS "windows" -Arch "amd64" -WithGPU $GPU
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Output directory: $outputDir" -ForegroundColor Cyan
