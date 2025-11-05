package dns

import (
	"fmt"
	"net"
	"reflect"
	"strings"
)

// Result represents the outcome of a DNS lookup for a hostname.
type Result struct {
	Hostname string
	Addrs    []string
	TXTs     []string
	CNAME    string // Per RFC, there should only be one CNAME
}

// LookupOptions configures what types of DNS records to look up.
type LookupOptions struct {
	LookupA     bool
	LookupTXT   bool
	LookupCNAME bool
	Wildcard    []string // Wildcard IPs to filter out
}

// Lookup performs DNS lookups for a subdomain with the given options.
// Returns nil if no records were found or if results match wildcard.
func Lookup(subdomain, baseDomain string, opts LookupOptions) *Result {
	hostname := fmt.Sprintf("%s.%s", subdomain, baseDomain)
	result := &Result{
		Hostname: hostname,
	}

	foundAny := false

	// A record lookup
	if opts.LookupA {
		if addrs, err := net.LookupHost(hostname); err == nil {
			// Skip if this matches the wildcard
			if reflect.DeepEqual(addrs, opts.Wildcard) {
				return nil
			}
			result.Addrs = addrs
			foundAny = true
		}
	}

	// TXT record lookup
	if opts.LookupTXT {
		if txts, err := net.LookupTXT(hostname); err == nil {
			result.TXTs = txts
			foundAny = true
		}
	}

	// CNAME lookup
	if opts.LookupCNAME {
		if cname, err := net.LookupCNAME(hostname); err == nil {
			trimmedCNAME := strings.TrimRight(cname, ".")
			// Only set CNAME if it's different from the hostname
			if trimmedCNAME != hostname {
				result.CNAME = cname
				foundAny = true
			}
		}
	}

	if !foundAny {
		return nil
	}

	return result
}
