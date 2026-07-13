package app

import (
	"os"
	"strings"
)

func preferredEnvironmentValue(primary, legacy string) string {
	if value, ok := os.LookupEnv(primary); ok {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(os.Getenv(legacy))
}
