package app

import (
	"fmt"
	"net/http"
	"strings"
)

func requestedResourceEnabled(r *http.Request) (*bool, error) {
	if !strings.HasSuffix(r.URL.Path, "/enabled") {
		return nil, nil
	}
	values := r.URL.Query()["enabled"]
	if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
		return nil, fmt.Errorf("enabled must be true or false")
	}
	enabled := values[0] == "true"
	return &enabled, nil
}
