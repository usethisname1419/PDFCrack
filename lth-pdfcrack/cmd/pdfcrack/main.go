package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lth/pdfcrack/internal/attacks"
	"github.com/lth/pdfcrack/internal/cracker"
	"github.com/lth/pdfcrack/internal/gpu"
	"github.com/lth/pdfcrack/internal/pdf"
	"github.com/spf13/cobra"
)

var (
	version = "1.2.0"

	pdfFile   string
	wordlist  string
	charset   string
	minLength int
	maxLength int
	workers   int
	useGPU    bool
	batchSize int
	verbose   bool

	useWordlist    bool
	useIncremental bool
	useRandom      bool
)

type modeStatus struct {
	attempts uint64
	rate     float64
	current  string
	active   bool
}

type attackResult struct {
	mode   string
	result cracker.Result
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "pdfcrack",
		Short: "LTH PDF Password Cracker - Fast PDF password recovery tool",
		Long: `LTH PDF Password Cracker v` + version + `
A high-performance PDF password recovery tool written in Go.
Supports CPU multi-threading and optional GPU acceleration.

Run one or more attack modes simultaneously:
  --wordlist (-W)     Dictionary attack using a wordlist file
  --incremental (-I)  Brute-force through all combinations  
  --random (-R)       Random password generation

Examples:
  pdfcrack -f doc.pdf -W -w rockyou.txt              # Wordlist only
  pdfcrack -f doc.pdf -I -c digits -m 4 -M 6         # Incremental only
  pdfcrack -f doc.pdf -W -I -w list.txt              # Wordlist + Incremental
  pdfcrack -f doc.pdf -W -I -R -w list.txt           # All three modes`,
		Run: runCracker,
	}

	rootCmd.Flags().StringVarP(&pdfFile, "file", "f", "", "PDF file to crack (required)")
	rootCmd.Flags().StringVarP(&wordlist, "wordlist-file", "w", "", "Wordlist file for dictionary attack")
	rootCmd.Flags().StringVarP(&charset, "charset", "c", "alnum", "Character set: lower, upper, digits, alnum, all, or custom")
	rootCmd.Flags().IntVarP(&minLength, "min", "m", 1, "Minimum password length")
	rootCmd.Flags().IntVarP(&maxLength, "max", "M", 8, "Maximum password length")
	rootCmd.Flags().IntVarP(&workers, "workers", "t", runtime.NumCPU(), "Number of CPU worker threads")
	rootCmd.Flags().BoolVarP(&useGPU, "gpu", "g", false, "Enable GPU acceleration (requires OpenCL)")
	rootCmd.Flags().IntVarP(&batchSize, "batch", "b", 10000, "GPU batch size")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.Flags().BoolVarP(&useWordlist, "use-wordlist", "W", false, "Enable wordlist/dictionary attack")
	rootCmd.Flags().BoolVarP(&useIncremental, "use-incremental", "I", false, "Enable incremental brute-force attack")
	rootCmd.Flags().BoolVarP(&useRandom, "use-random", "R", false, "Enable random password attack")

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

	if !useWordlist && !useIncremental && !useRandom {
		fmt.Fprintln(os.Stderr, "Error: No attack mode selected.")
		fmt.Fprintln(os.Stderr, "Use one or more of: -W (wordlist), -I (incremental), -R (random)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  pdfcrack -f doc.pdf -W -w wordlist.txt")
		fmt.Fprintln(os.Stderr, "  pdfcrack -f doc.pdf -I -c digits -m 4 -M 6")
		fmt.Fprintln(os.Stderr, "  pdfcrack -f doc.pdf -W -I -R -w wordlist.txt")
		os.Exit(1)
	}

	if useWordlist && wordlist == "" {
		fmt.Fprintln(os.Stderr, "Error: Wordlist mode requires -w <wordlist_file>")
		os.Exit(1)
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

	var modes []string
	if useWordlist {
		modes = append(modes, "Wordlist")
	}
	if useIncremental {
		modes = append(modes, "Incremental")
	}
	if useRandom {
		modes = append(modes, "Random")
	}
	fmt.Printf("Modes: %s\n", strings.Join(modes, " + "))
	fmt.Printf("Workers: %d per mode\n", workers)

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

	fmt.Println()
	fmt.Println("Starting attack(s)... Press Ctrl+C to stop.")
	fmt.Println()

	numModes := 0
	if useWordlist {
		numModes++
	}
	if useIncremental {
		numModes++
	}
	if useRandom {
		numModes++
	}

	fmt.Println("┌─────────────┬──────────────┬──────────────┬──────────────────────┐")
	fmt.Println("│ Mode        │ Attempts     │ Speed        │ Current              │")
	fmt.Println("├─────────────┼──────────────┼──────────────┼──────────────────────┤")
	for i := 0; i < numModes; i++ {
		fmt.Println("│             │              │              │                      │")
	}
	fmt.Println("└─────────────┴──────────────┴──────────────┴──────────────────────┘")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	resultChan := make(chan attackResult, 3)
	var wg sync.WaitGroup

	statusMu := sync.Mutex{}
	statuses := map[string]*modeStatus{
		"Wordlist":    {active: useWordlist},
		"Incremental": {active: useIncremental},
		"Random":      {active: useRandom},
	}

	updateStatus := func(mode string, attempts uint64, rate float64, current string) {
		statusMu.Lock()
		if s, ok := statuses[mode]; ok {
			s.attempts = attempts
			s.rate = rate
			s.current = current
		}
		statusMu.Unlock()
	}

	stopDisplay := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		fmt.Print("\033[?25l")

		for {
			select {
			case <-stopDisplay:
				fmt.Print("\033[?25h")
				return
			case <-ticker.C:
				statusMu.Lock()
				printStatusTable(statuses, numModes)
				statusMu.Unlock()
			}
		}
	}()

	if useWordlist {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := runWordlistAttack(ctx, encInfo, gpuCracker, updateStatus)
			resultChan <- attackResult{mode: "Wordlist", result: result}
			if result.Found {
				cancel()
			}
		}()
	}

	if useIncremental {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := runIncrementalAttack(ctx, encInfo, updateStatus)
			resultChan <- attackResult{mode: "Incremental", result: result}
			if result.Found {
				cancel()
			}
		}()
	}

	if useRandom {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := runRandomAttack(ctx, encInfo, updateStatus)
			resultChan <- attackResult{mode: "Random", result: result}
			if result.Found {
				cancel()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(stopDisplay)
		close(resultChan)
	}()

	var foundResult *attackResult
	var allResults []attackResult

	for res := range resultChan {
		allResults = append(allResults, res)
		if res.result.Found && foundResult == nil {
			foundResult = &res
		}
	}

	fmt.Print("\033[?25h")
	fmt.Println()
	fmt.Println()
	fmt.Println("================================")
	fmt.Println("RESULTS")
	fmt.Println("================================")

	if foundResult != nil {
		fmt.Printf("\n*** PASSWORD FOUND: %s ***\n", foundResult.result.Password)
		fmt.Printf("Found by: %s attack\n", foundResult.mode)
		fmt.Printf("Time: %s\n", formatDuration(foundResult.result.Duration))
		fmt.Printf("Attempts: %d\n", foundResult.result.Attempts)
	} else {
		fmt.Println("\nPassword not found.")
	}

	fmt.Println("\nPer-mode statistics:")
	var totalAttempts uint64
	for _, res := range allResults {
		rate := float64(res.result.Attempts) / res.result.Duration.Seconds()
		fmt.Printf("  %-12s: %d attempts in %s (%.0f p/s)\n",
			res.mode, res.result.Attempts, formatDuration(res.result.Duration), rate)
		totalAttempts += res.result.Attempts
	}
	fmt.Printf("\nTotal attempts: %d\n", totalAttempts)
}

func printStatusTable(statuses map[string]*modeStatus, numModes int) {
	fmt.Printf("\033[%dA", numModes+1)

	modeOrder := []string{"Wordlist", "Incremental", "Random"}
	for _, mode := range modeOrder {
		s := statuses[mode]
		if s.active {
			fmt.Printf("\r│ %-11s │ %12d │ %10.0f/s │ %-20s │\033[K\n",
				mode, s.attempts, s.rate, truncate(s.current, 20))
		}
	}
	fmt.Print("└─────────────┴──────────────┴──────────────┴──────────────────────┘\033[K")
}

func runWordlistAttack(ctx context.Context, encInfo *pdf.EncryptionInfo, gpuCracker *gpu.GPUCracker, updateStatus func(string, uint64, float64, string)) cracker.Result {
	c := cracker.New(encInfo, workers)

	c.SetProgressCallback(func(p cracker.Progress) {
		updateStatus("Wordlist", p.Attempts, p.Rate, p.Current)
	})

	if useGPU && gpuCracker != nil {
		return crackWithGPU(ctx, gpuCracker, wordlist, updateStatus)
	}

	passwords, err := attacks.WordlistGenerator(ctx, wordlist)
	if err != nil {
		updateStatus("Wordlist", 0, 0, fmt.Sprintf("Error: %v", err))
		return cracker.Result{}
	}

	return c.CrackWithWordlist(ctx, passwords)
}

func runIncrementalAttack(ctx context.Context, encInfo *pdf.EncryptionInfo, updateStatus func(string, uint64, float64, string)) cracker.Result {
	c := cracker.New(encInfo, workers)

	charsetStr := resolveCharset(charset)
	config := attacks.IncrementalConfig{
		Charset:   charsetStr,
		MinLength: minLength,
		MaxLength: maxLength,
	}

	c.SetProgressCallback(func(p cracker.Progress) {
		updateStatus("Incremental", p.Attempts, p.Rate, p.Current)
	})

	generator := func(ctx context.Context) <-chan string {
		return attacks.IncrementalGenerator(ctx, config)
	}

	return c.CrackWithGenerator(ctx, generator)
}

func runRandomAttack(ctx context.Context, encInfo *pdf.EncryptionInfo, updateStatus func(string, uint64, float64, string)) cracker.Result {
	c := cracker.New(encInfo, workers)

	charsetStr := resolveCharset(charset)
	config := attacks.RandomConfig{
		Charset:   charsetStr,
		MinLength: minLength,
		MaxLength: maxLength,
	}

	c.SetProgressCallback(func(p cracker.Progress) {
		updateStatus("Random", p.Attempts, p.Rate, p.Current)
	})

	generator := func(ctx context.Context) <-chan string {
		return attacks.RandomGenerator(ctx, config)
	}

	return c.CrackWithGenerator(ctx, generator)
}

func crackWithGPU(ctx context.Context, gpuCracker *gpu.GPUCracker, wordlistFile string, updateStatus func(string, uint64, float64, string)) cracker.Result {
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

				elapsed := time.Since(start)
				rate := float64(attempts) / elapsed.Seconds()
				updateStatus("Wordlist", attempts, rate, "[GPU]")
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
