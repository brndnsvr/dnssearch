// Package scanner orchestrates the subdomain enumeration process.
package scanner

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/evilsocket/brutemachine"
	"github.com/evilsocket/dnssearch/internal/config"
	"github.com/evilsocket/dnssearch/internal/dns"
	"github.com/evilsocket/dnssearch/internal/output"
)

// Scanner coordinates the subdomain enumeration process.
type Scanner struct {
	config    *config.Config
	formatter *output.Formatter
	machine   *brutemachine.Machine
	wildcard  []string
	startTime time.Time
}

// New creates a new Scanner with the given configuration.
func New(cfg *config.Config, formatter *output.Formatter) *Scanner {
	return &Scanner{
		config:    cfg,
		formatter: formatter,
	}
}

// Setup performs initialization before scanning begins.
func (s *Scanner) Setup() error {
	s.startTime = time.Now()

	// Detect wildcard DNS
	hasWildcard, wildcard, _ := dns.DetectWildcard(s.config.Domain)
	if hasWildcard {
		s.wildcard = wildcard
		s.formatter.PrintWildcard(wildcard)
	}

	return nil
}

// doRequest is called by brutemachine for each subdomain.
func (s *Scanner) doRequest(sub string) interface{} {
	opts := dns.LookupOptions{
		LookupA:     s.config.SearchA,
		LookupTXT:   s.config.SearchTXT,
		LookupCNAME: s.config.SearchCNAME,
		Wildcard:    s.wildcard,
	}

	return dns.Lookup(sub, s.config.Domain, opts)
}

// onResult is called by brutemachine when a result is found.
func (s *Scanner) onResult(res interface{}) {
	result, ok := res.(*dns.Result)
	if !ok || result == nil {
		return
	}

	s.formatter.PrintResult(result)
}

// Run starts the scanning process.
func (s *Scanner) Run() error {
	// Setup signal handling for graceful shutdown
	s.setupSignalHandler()

	// Create and start the brutemachine
	s.machine = brutemachine.New(
		s.config.Consumers,
		s.config.Wordlist,
		s.doRequest,
		s.onResult,
	)

	if err := s.machine.Start(); err != nil {
		return err
	}

	s.machine.Wait()

	return nil
}

// PrintStats prints final statistics.
func (s *Scanner) PrintStats() {
	if s.machine != nil {
		s.machine.UpdateStats()
		duration := time.Since(s.startTime)
		s.formatter.PrintStats(
			s.machine.Stats.Execs,
			s.machine.Stats.Results,
			duration,
		)
	}
}

// setupSignalHandler configures interrupt handling.
func (s *Scanner) setupSignalHandler() {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		s.formatter.PrintInterrupt()
		s.PrintStats()
		os.Exit(0)
	}()
}
