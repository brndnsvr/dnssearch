// Package output handles formatting and displaying scan results.
package output

import (
	"fmt"
	"time"

	"github.com/evilsocket/dnssearch/internal/dns"
	"github.com/fatih/color"
)

// Formatter handles output formatting with color support.
type Formatter struct {
	green *color.Color
	red   *color.Color

	showA     bool
	showTXT   bool
	showCNAME bool
}

// New creates a new Formatter with the specified options.
func New(showA, showTXT, showCNAME bool) *Formatter {
	return &Formatter{
		green:     color.New(color.FgGreen),
		red:       color.New(color.FgRed),
		showA:     showA,
		showTXT:   showTXT,
		showCNAME: showCNAME,
	}
}

// PrintBanner prints the application banner.
func (f *Formatter) PrintBanner(version string) {
	_, _ = f.red.Printf("dnssearch")
	fmt.Printf(" v%s\n\n", version)
}

// PrintWildcard prints information about detected wildcard records.
func (f *Formatter) PrintWildcard(wildcard []string) {
	fmt.Printf("Detected Wildcard : %v\n\n", wildcard)
}

// PrintResult formats and prints a DNS lookup result.
func (f *Formatter) PrintResult(result *dns.Result) {
	if result == nil {
		return
	}

	_, _ = f.green.Printf("%25s", result.Hostname)

	if f.showA && len(result.Addrs) > 0 {
		fmt.Printf(" : A %v", result.Addrs)
	}

	if f.showTXT && len(result.TXTs) > 0 {
		fmt.Printf(" : TXT %v", result.TXTs)
	}

	if f.showCNAME && result.CNAME != "" {
		fmt.Printf(" : CNAME %v", result.CNAME)
	}

	fmt.Printf("\n")
}

// PrintStats prints final statistics about the scan.
func (f *Formatter) PrintStats(requests, results uint64, duration time.Duration) {
	_, _ = f.green.Println("\nDONE")

	fmt.Println("")
	fmt.Println("Requests :", requests)
	fmt.Println("Results  :", results)
	fmt.Println("Time     :", duration.Seconds(), "s")

	if duration.Seconds() > 0 {
		rps := float64(requests) / duration.Seconds()
		fmt.Printf("Req/s    : %.2f\n", rps)
	}
}

// PrintInterrupt prints an interruption message.
func (f *Formatter) PrintInterrupt() {
	_, _ = f.red.Println("\nINTERRUPTING ...")
}

// PrintError prints an error message.
func (f *Formatter) PrintError(msg string) {
	_, _ = f.red.Printf("%s\n", msg)
}
