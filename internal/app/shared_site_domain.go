package app

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

func normalizeSharedSiteDomain(domain string) (string, error) {
	domain, err := idna.Lookup.ToASCII(strings.TrimSpace(domain))
	if err != nil {
		return "", fmt.Errorf("domain must be a valid DNS hostname")
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" || len(domain) > 253 {
		return "", fmt.Errorf("domain must be a valid DNS hostname")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain must be a valid DNS hostname")
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return "", fmt.Errorf("domain must be a valid DNS hostname")
			}
		}
	}
	return domain, nil
}
