// Package dns provides DNS lookup functionality for subdomain enumeration.
package dns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
)

// DetectWildcard checks if a domain has wildcard A records configured.
// It does this by looking up a random subdomain and seeing if it resolves.
// Returns: hasWildcard, wildcardAddresses, error
//
// Adapted from https://github.com/jrozner/sonar/blob/master/wildcard.go
func DetectWildcard(domain string) (bool, []string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return false, nil, err
	}

	randomDomain := fmt.Sprintf("%s.%s", hex.EncodeToString(bytes), domain)

	answers, err := net.LookupHost(randomDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.Err == "no such host" {
			return false, nil, nil
		}
		return false, nil, err
	}

	return true, answers, nil
}
