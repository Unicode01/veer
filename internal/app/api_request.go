package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const (
	apiJSONBodyMaxBytes      int64 = 1 << 20
	apiJSONBatchBodyMaxBytes int64 = 4 << 20
)

func decodeJSONRequestBody(w http.ResponseWriter, r *http.Request, target interface{}, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = apiJSONBodyMaxBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing json payload")
		}
		return err
	}
	return nil
}
