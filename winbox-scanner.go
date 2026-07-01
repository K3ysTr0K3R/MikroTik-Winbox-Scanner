package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	ipFlag      = flag.String("ip", "", "Single IP or CIDR subnet (e.g., 192.168.1.1 or 192.168.1.0/24)")
	fileFlag    = flag.String("f", "", "File containing list of IPs (one per line)")
	threadsFlag = flag.Int("t", 100, "Number of concurrent workers")
	outputFlag  = flag.String("o", "", "Output file for results")
	appendFlag  = flag.Bool("append", false, "Append results to output file instead of overwriting")
	portFlag    = flag.Int("p", 8291, "Winbox port (default 8291)")
	timeoutFlag = flag.Duration("timeout", 5*time.Second, "Connection timeout")

	completed  int64
	totalJobs  int64
	progressMu sync.Mutex
)

var (
	cyan    = color.New(color.FgCyan, color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	white   = color.New(color.FgWhite, color.Bold)
	gray    = color.New(color.FgHiBlack)
)

func printHeader() {
	yellow.Print("[!] ")
	white.Printf("Winbox Scanner for MikroTik (RouterOS)\n")
	white.Printf("    Coded By: K3ysTr0K3R\n\n")
}

func detectWinbox(ip string, port int, timeout time.Duration) (bool, string) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	probeModern := []byte{0x22, 0x06}
	probeModern = append(probeModern, make([]byte, 34)...)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(probeModern); err != nil {
		return false, ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n >= 2 && buf[0] == 0x21 && buf[1] == 0x06 {
		return true, "Modern (RouterOS v6.43+)"
	}

	probeLegacy := []byte{0xF8, 0x05}
	probeLegacy = append(probeLegacy, make([]byte, 248)...)

	conn, err = net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(probeLegacy); err != nil {
		return false, ""
	}
	n, err = conn.Read(buf)
	if err == nil && n >= 2 && buf[0] == 0xF8 && buf[1] == 0x05 {
		return true, "Legacy (RouterOS < v6.43)"
	}
	return false, ""
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		return []string{ip.String()}, nil
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}

func progressUpdater(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			progressMu.Lock()
			fmt.Fprintf(os.Stderr, "\r\033[K")
			progressMu.Unlock()
			return
		case <-ticker.C:
			done := atomic.LoadInt64(&completed)
			total := totalJobs
			if total == 0 {
				total = 1
			}
			pct := float64(done) / float64(total) * 100
			barWidth := 40
			filled := int(float64(barWidth) * float64(done) / float64(total))
			if filled > barWidth {
				filled = barWidth
			}

			fillStr := strings.Repeat("█", filled)
			emptyStr := strings.Repeat("░", barWidth-filled)
			coloredBar := green.Sprintf("%s%s", fillStr, gray.Sprintf("%s", emptyStr))

			pctStr := yellow.Sprintf("%3.0f%%", pct)
			countStr := white.Sprintf("%d/%d", done, total)

			progressMu.Lock()
			white.Fprintf(os.Stderr, "\r\033[KScanning hosts: [%s] %s (%s)", coloredBar, pctStr, countStr)
			progressMu.Unlock()
		}
	}
}

func main() {
	flag.Parse()

	printHeader()

	var targets []string
	seen := make(map[string]bool)

	if *ipFlag != "" {
		if strings.Contains(*ipFlag, "/") {
			ips, err := expandCIDR(*ipFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid CIDR: %v\n", err)
				os.Exit(1)
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					targets = append(targets, ip)
				}
			}
		} else {
			if net.ParseIP(*ipFlag) != nil {
				if !seen[*ipFlag] {
					seen[*ipFlag] = true
					targets = append(targets, *ipFlag)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Invalid IP: %s\n", *ipFlag)
				os.Exit(1)
			}
		}
	}

	if *fileFlag != "" {
		fileIPs, err := readIPsFromFile(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		for _, ip := range fileIPs {
			if net.ParseIP(ip) == nil {
				fmt.Fprintf(os.Stderr, "Skipping invalid IP: %s\n", ip)
				continue
			}
			if !seen[ip] {
				seen[ip] = true
				targets = append(targets, ip)
			}
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No targets specified. Use -ip or -f.")
		os.Exit(1)
	}

	var outFile *os.File
	var err error
	if *outputFlag != "" {
		flagMode := os.O_CREATE | os.O_WRONLY
		if *appendFlag {
			flagMode |= os.O_APPEND
		} else {
			flagMode |= os.O_TRUNC
		}
		outFile, err = os.OpenFile(*outputFlag, flagMode, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	totalJobs = int64(len(targets))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go progressUpdater(ctx)

	targetCh := make(chan string, 100)
	resultCh := make(chan struct {
		ip      string
		version string
	}, 100)

	var wg sync.WaitGroup
	workers := *threadsFlag
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(targetCh, resultCh, &wg)
	}

	go func() {
		for _, ip := range targets {
			targetCh <- ip
		}
		close(targetCh)
	}()

	var resultsMu sync.Mutex
	resultsCount := 0
	done := make(chan struct{})
	go func() {
		for res := range resultCh {
			resultsMu.Lock()

			progressMu.Lock()
			fmt.Fprintf(os.Stderr, "\r\033[K")
			progressMu.Unlock()

			green.Print("[FOUND] ")
			cyan.Printf("%s:%d", res.ip, *portFlag)
			fmt.Print(" -> ")
			yellow.Print("Winbox (MikroTik - RouterOS)")
			fmt.Println()

			if outFile != nil {
				line := fmt.Sprintf("[FOUND] %s:%d -> Winbox (MikroTik - RouterOS)\n", res.ip, *portFlag)
				if _, err := outFile.WriteString(line); err != nil {
					fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
				}
			}
			resultsCount++
			resultsMu.Unlock()
		}
		close(done)
	}()

	wg.Wait()
	close(resultCh)
	<-done

	cancel()
	time.Sleep(50 * time.Millisecond)
	progressMu.Lock()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	progressMu.Unlock()

	fmt.Println()
	yellow.Print("[!] ")
	white.Print("Scan completed. ")
	white.Printf("%d", totalJobs)
	fmt.Print(" targets scanned, ")
	green.Printf("%d", resultsCount)
	white.Println(" Winbox instances found.")
}

func worker(targetCh <-chan string, resultCh chan<- struct {
	ip      string
	version string
}, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range targetCh {
		ok, version := detectWinbox(ip, *portFlag, *timeoutFlag)
		if ok {
			resultCh <- struct {
				ip      string
				version string
			}{ip, version}
		}
		atomic.AddInt64(&completed, 1)
	}
}
