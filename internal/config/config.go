// Package config handles application configuration and command-line flags.
package config

import (
	"flag"
	"fmt"

	"github.com/bobesa/go-domain-util/domainutil"
)

// Config holds all configuration options for the scanner.
type Config struct {
	Domain      string
	Wordlist    string
	Consumers   int
	SearchTXT   bool
	SearchCNAME bool
	SearchA     bool
	ForceTLD    bool
}

// New parses command-line flags and returns a new Config.
func New() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Domain, "domain", "", "Base domain to start enumeration from.")
	flag.StringVar(&cfg.Wordlist, "wordlist", "names.txt", "Wordlist file to use for enumeration.")
	flag.IntVar(&cfg.Consumers, "consumers", 8, "Number of concurrent consumers.")
	flag.BoolVar(&cfg.SearchTXT, "txt", false, "Search for TXT records")
	flag.BoolVar(&cfg.SearchCNAME, "cname", false, "Show CNAME results")
	flag.BoolVar(&cfg.SearchA, "a", true, "Show A results")
	flag.BoolVar(&cfg.ForceTLD, "force-tld", true, "Extract top level from provided domain")

	flag.Parse()

	return cfg
}

// Validate checks if the configuration is valid and normalizes the domain.
func (c *Config) Validate() error {
	if c.ForceTLD {
		c.Domain = domainutil.Domain(c.Domain)
	}

	if c.Domain == "" {
		fmt.Println("Invalid or empty domain specified.")
		flag.Usage()
		return fmt.Errorf("domain is required")
	}

	return nil
}
