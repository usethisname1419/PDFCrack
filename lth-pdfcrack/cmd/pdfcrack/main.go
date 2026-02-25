package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/lth/pdfcrack/internal/attacks"
	"github.com/lth/pdfcrack/internal/cracker"
	"github.com/lth/pdfcrack/internal/gpu"
	"github.com/lth/pdfcrack/internal/pdf"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	
	pdfFile     string
	wordlist    string
	charset     string
	minLength   int
	maxLength   int
	workers     int
	useGPU      bool
	batchSize   int
	mode        string
	verbose     bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pdfcrack",
		Short: "LTH PDF Password Cracker - Fast PDF password recovery tool",
		Long: `LTH PDF Password Cracker v` + version + `
A high-performance PDF password recovery tool written in Go.
Supports CPU multi-threading and optional GPU acceleration.

Supports PDF encryption versions 1-4 (R2-R4).`,
		Run: runCracker,
	}

	rootCmd.Flags().StringVarP(&pdfFile, "file", "f", "", "PDF file to crack (required)")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist file for dictionary attack")
	rootCmd.Flags().StringVarP(&charset, "charset", "c", "alnum", "Character set: lower, upper, digits, alnum, all, or custom string")
	rootCmd.Flags().IntVarP(&minLength, "min", "m", 1, "Minimum password length for brute-force")
	rootCmd.Flags().IntVarP(&maxLength, "max", "M", 8, "Maximum password length for brute-force")
	rootCmd.Flags().IntVarP(&workers, "workers", "t", runtime.NumCPU(), "Number of CPU worker threads")
	rootCmd.Flags().BoolVarP(&useGPU, "gpu", "g", false, "Enable GPU acceleration (requires OpenCL)")
	rootCmd.Flags().IntVarP(&batchSize, "batch", "b", 10000, "GPU batch size")
	rootCmd.Flags().StringVarP(&mode, "mode", "a", "wordlist", "Attack mode: wordlist, incremental, random")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.MarkFlagRequired("file")

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Display PDF encryption information",
		Run:   runInfo,
	}
	infoCmd.Flags().StringVarP(&pdfFile, "file", "f", "", "PDF file to analyze (required)")
	infoCmd.MarkFlagRequired("file")

	benchCmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run performance benchmark",
		Run:   runBenchmark,
	}
	benchCmd.Flags().StringVarP(&pdfFile, "file", "f", "", "PDF file for benchmark (required)")
	benchCmd.Flags().IntVarP(&workers, "workers", "t", runtime.NumCPU(), "Number of CPU worker threads")
	benchCmd.Flags().BoolVarP(&useGPU, "gpu", "g", false, "Benchmark GPU mode")
	benchCmd.MarkFlagRequired("file")

	rootCmd.AddCommand(infoCmd, benchCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runInfo(cmd *cobra.Command, args []string) {
	encInfo, err := pdf.ExtractEncryptionInfo(pdfFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("PDF Encryption Information")
	fmt.Println("==========================")
	fmt.Printf("File:        %s\n", pdfFile)
	fmt.Printf("PDF Version: %s\n", encInfo.PDFVersion)
	fmt.Printf("Encryption:  V%d R%d\n", encInfo.Version, encInfo.Revision)
	fmt.Printf("Key Length:  %d bits\n", encInfo.Length)
	fmt.Printf("Algorithm:   %s\n", map[bool]string{true: "AES", false: "RC4"}[encInfo.IsAES])
	fmt.Printf("Permissions: %d\n", encInfo.Permissions)
	fmt.Printf("Owner Hash:  %x\n", encInfo.OwnerHash)
	fmt.Printf("User Hash:   %x\n", encInfo.UserHash)
	fmt.Printf("File ID:     %x\n", encInfo.FileID)
}

func runBenchmark(cmd *cobra.Command, args []string) {
	encInfo, err := pdf.ExtractEncryptionInfo(pdfFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Benchmarking with %d workers...\n", workers)

	c := cracker.New(encInfo, workers)
	
	testPasswords := make([]string, 100000)
	for i := range testPasswords {
		testPasswords[i] = fmt.Sprintf("test%d", i)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	passwords := attacks.SliceGenerator(ctx, testPasswords)
	c.CrackWithWordlist(ctx, passwords)
	elapsed := time.Since(start)

	rate := float64(len(testPasswords)) / elapsed.Seconds()
	fmt.Printf("CPU Mode: %.0f passwords/second\n", rate)

	if useGPU {
		gpuCracker, err := gpu.NewGPUCracker(encInfo, batchSize)
		if err != nil {
			fmt.Printf("GPU Mode: %v\n", err)
		} else {
			defer gpuCracker.Close()
			fmt.Printf("GPU Device: %s\n", gpuCracker.DeviceInfo())

			start = time.Now()
			for i := 0; i < 10; i++ {
				gpuCracker.CrackBatch(testPasswords[:batchSize])
			}
			elapsed = time.Since(start)
			rate = float64(batchSize*10) / elapsed.Seconds()
			fmt.Printf("GPU Mode: %.0f passwords/second\n", rate)
		}
	}
}

func runCracker(cmd *cobra.Command, args []string) {
	if pdfFile == "" {
		cmd.Help()
		return
	}

	fmt.Printf("LTH PDF Password Cracker v%s\n", version)
	fmt.Println("================================")

	encInfo, err := pdf.ExtractEncryptionInfo(pdfFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File: %s\n", pdfFile)
	fmt.Printf("Encryption: %s\n", encInfo.String())
	fmt.Printf("Workers: %d\n", workers)
	fmt.Println()

	var gpuCracker *gpu.GPUCracker
	if useGPU {
		gpuCracker, err = gpu.NewGPUCracker(encInfo, batchSize)
		if err != nil {
			fmt.Printf("GPU initialization failed: %v\n", err)
			fmt.Println("Falling back to CPU mode...")
			useGPU = false
		} else {
			defer gpuCracker.Close()
			fmt.Printf("GPU: %s\n", gpuCracker.DeviceInfo())
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted - stopping...")
		cancel()
	}()

	c := cracker.New(encInfo, workers)
	
	lastReport := time.Now()
	c.SetProgressCallback(func(p cracker.Progress) {
		if time.Since(lastReport) > 500*time.Millisecond {
			fmt.Printf("\r[%s] %d attempts | %.0f p/s | Current: %s",
				formatDuration(p.ElapsedTime), p.Attempts, p.Rate, truncate(p.Current, 20))
			lastReport = time.Now()
		}
	})

	var result cracker.Result

	switch mode {
	case "wordlist":
		if wordlist == "" {
			fmt.Fprintln(os.Stderr, "Error: Wordlist required for wordlist mode (-w)")
			os.Exit(1)
		}
		fmt.Printf("Mode: Wordlist attack (%s)\n", wordlist)
		
		if useGPU && gpuCracker != nil {
			result = crackWithGPU(ctx, gpuCracker, wordlist)
		} else {
			passwords, err := attacks.WordlistGenerator(ctx, wordlist)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			result = c.CrackWithWordlist(ctx, passwords)
		}

	case "incremental":
		charsetStr := resolveCharset(charset)
		config := attacks.IncrementalConfig{
			Charset:   charsetStr,
			MinLength: minLength,
			MaxLength: maxLength,
		}
		
		estimate := attacks.EstimateCombinations(config)
		fmt.Printf("Mode: Incremental brute-force\n")
		fmt.Printf("Charset: %d characters, Length: %d-%d\n", len(charsetStr), minLength, maxLength)
		fmt.Printf("Estimated combinations: %d\n", estimate)
		
		generator := func(ctx context.Context) <-chan string {
			return attacks.IncrementalGenerator(ctx, config)
		}
		result = c.CrackWithGenerator(ctx, generator)

	case "random":
		charsetStr := resolveCharset(charset)
		config := attacks.RandomConfig{
			Charset:   charsetStr,
			MinLength: minLength,
			MaxLength: maxLength,
		}
		
		fmt.Printf("Mode: Random attack\n")
		fmt.Printf("Charset: %d characters, Length: %d-%d\n", len(charsetStr), minLength, maxLength)
		
		generator := func(ctx context.Context) <-chan string {
			return attacks.RandomGenerator(ctx, config)
		}
		result = c.CrackWithGenerator(ctx, generator)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown mode '%s'\n", mode)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println()

	if result.Found {
		fmt.Println("================================")
		fmt.Printf("PASSWORD FOUND: %s\n", result.Password)
		fmt.Println("================================")
		fmt.Printf("Time: %s\n", formatDuration(result.Duration))
		fmt.Printf("Attempts: %d\n", result.Attempts)
		fmt.Printf("Rate: %.0f passwords/second\n", float64(result.Attempts)/result.Duration.Seconds())
	} else {
		fmt.Println("Password not found.")
		fmt.Printf("Attempts: %d\n", result.Attempts)
		fmt.Printf("Time: %s\n", formatDuration(result.Duration))
	}
}

func crackWithGPU(ctx context.Context, gpuCracker *gpu.GPUCracker, wordlistFile string) cracker.Result {
	start := time.Now()
	var attempts uint64

	passwords, err := attacks.WordlistGenerator(ctx, wordlistFile)
	if err != nil {
		return cracker.Result{Duration: time.Since(start)}
	}

	batch := make([]string, 0, batchSize)
	
	for {
		select {
		case <-ctx.Done():
			return cracker.Result{
				Attempts: attempts,
				Duration: time.Since(start),
			}
		case pwd, ok := <-passwords:
			if !ok {
				if len(batch) > 0 {
					if found, ok := gpuCracker.CrackBatch(batch); ok {
						return cracker.Result{
							Found:    true,
							Password: found,
							Attempts: attempts + uint64(len(batch)),
							Duration: time.Since(start),
						}
					}
					attempts += uint64(len(batch))
				}
				return cracker.Result{
					Attempts: attempts,
					Duration: time.Since(start),
				}
			}

			batch = append(batch, pwd)
			if len(batch) >= batchSize {
				if found, ok := gpuCracker.CrackBatch(batch); ok {
					return cracker.Result{
						Found:    true,
						Password: found,
						Attempts: attempts + uint64(len(batch)),
						Duration: time.Since(start),
					}
				}
				attempts += uint64(len(batch))
				batch = batch[:0]
				
				if attempts%100000 == 0 {
					elapsed := time.Since(start)
					rate := float64(attempts) / elapsed.Seconds()
					fmt.Printf("\r[GPU] %d attempts | %.0f p/s", attempts, rate)
				}
			}
		}
	}
}

func resolveCharset(cs string) string {
	switch strings.ToLower(cs) {
	case "lower":
		return attacks.CharsetLower
	case "upper":
		return attacks.CharsetUpper
	case "digits", "numbers":
		return attacks.CharsetDigits
	case "alpha":
		return attacks.CharsetAlpha
	case "alnum", "alphanumeric":
		return attacks.CharsetAlphaNum
	case "all", "full":
		return attacks.CharsetAll
	case "special":
		return attacks.CharsetSpecial
	default:
		return cs
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
