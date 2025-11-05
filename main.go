// This software is a subdomain enumeration tool written by Simone Margaritelli
// (evilsocket at gmail dot com) and Copylefted under GPLv3 license.
package main

import (
	"log"
	"os"

	"github.com/evilsocket/dnssearch/internal/config"
	"github.com/evilsocket/dnssearch/internal/output"
	"github.com/evilsocket/dnssearch/internal/scanner"
)

// Version is the current version of dnssearch.
const Version = "1.1.0"

func main() {
	// Parse configuration
	cfg := config.New()

	// Create output formatter
	formatter := output.New(cfg.SearchA, cfg.SearchTXT, cfg.SearchCNAME)
	formatter.PrintBanner(Version)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		os.Exit(1)
	}

	// Create and setup scanner
	scan := scanner.New(cfg, formatter)
	if err := scan.Setup(); err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	// Run the scan
	if err := scan.Run(); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print final statistics
	scan.PrintStats()
}
