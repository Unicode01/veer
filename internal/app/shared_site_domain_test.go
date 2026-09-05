package app

import (
	"context"
	"strings"
	"testing"
)

func TestSharedSiteDomainNormalization(t *testing.T) {
	for _, input := range []string{"EXAMPLE.COM", " example.com. "} {
		got, err := normalizeSharedSiteDomain(input)
		if err != nil || got != "example.com" {
			t.Fatalf("domain %q: %q %v", input, got, err)
		}
	}
	for _, input := range []string{"", "a..test", "http://example.com", "example.com:80", "*.example.com", "bad_name.test", "-bad.test", strings.Repeat("a", 64) + ".test"} {
		if _, err := normalizeSharedSiteDomain(input); err == nil {
			t.Fatalf("accepted domain %q", input)
		}
	}
}

func TestSharedSiteHistoricalAliasCollisionFailsClosed(t *testing.T) {
	sp := &sharedProxyEngine{}
	result := sp.applySites(context.Background(), []Site{
		{ID: 1, Domain: "a.test", BackendHTTP: 80, BackendIP: "192.0.2.1"},
		{ID: 2, Domain: "A.TEST.", BackendHTTP: 80, BackendIP: "192.0.2.2"},
	}, 1)
	if len(result.failedSiteIDs) != 2 || len(sp.httpRoutes) != 0 {
		t.Fatalf("historical aliases silently overwrote route: %+v", result)
	}
	if got := sp.listenerStatusLocked(); len(got.failedSiteIDs) != 2 {
		t.Fatalf("historical collision status cleared: %+v", got)
	}
}
