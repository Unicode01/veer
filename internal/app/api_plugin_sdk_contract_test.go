package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestPluginSDKContractAPIRequiresAuthAndMatchesRuntime(t *testing.T) {
	cfg := &Config{WebToken: "contract-token"}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)

	request := func(method, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/plugin-sdk-contract", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(http.MethodGet, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated contract status = %d", rec.Code)
	}
	if rec := request(http.MethodPost, cfg.WebToken); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("contract POST status = %d", rec.Code)
	}
	rec := request(http.MethodGet, cfg.WebToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("contract GET status = %d: %s", rec.Code, rec.Body.String())
	}
	var got pluginSDKAPIContract
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if want := currentPluginSDKAPIContract(); !reflect.DeepEqual(got, want) {
		t.Fatalf("contract API = %+v, want %+v", got, want)
	}
}
