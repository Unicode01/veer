package app

import "testing"

func TestPreferredEnvironmentValue(t *testing.T) {
	t.Setenv("VEER_TEST_VALUE", " primary ")
	t.Setenv("FORWARD_TEST_VALUE", "legacy")
	if got := preferredEnvironmentValue("VEER_TEST_VALUE", "FORWARD_TEST_VALUE"); got != "primary" {
		t.Fatalf("preferredEnvironmentValue() = %q, want primary", got)
	}

	t.Setenv("VEER_TEST_VALUE", "")
	if got := preferredEnvironmentValue("VEER_TEST_VALUE", "FORWARD_TEST_VALUE"); got != "" {
		t.Fatalf("explicit empty primary value = %q, want empty", got)
	}
}

func TestPreferredEnvironmentValueFallsBackToLegacy(t *testing.T) {
	t.Setenv("FORWARD_TEST_FALLBACK", " legacy ")
	if got := preferredEnvironmentValue("VEER_TEST_UNSET", "FORWARD_TEST_FALLBACK"); got != "legacy" {
		t.Fatalf("preferredEnvironmentValue() = %q, want legacy", got)
	}
}
