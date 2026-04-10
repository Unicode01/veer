package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newJSONRequest(t *testing.T, method, target string, body interface{}) *http.Request {
	t.Helper()

	if body == nil {
		return httptest.NewRequest(method, target, nil)
	}

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeValidationResponse(t *testing.T, w *httptest.ResponseRecorder) validationErrorResponse {
	t.Helper()

	var resp validationErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode validation response: %v body=%s", err, w.Body.String())
	}
	return resp
}

func decodeErrorResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, w.Body.String())
	}
	return resp
}

func assertValidationIssue(t *testing.T, resp validationErrorResponse, scope, field, message string) {
	t.Helper()

	if len(resp.Issues) == 0 {
		t.Fatalf("issues = %#v, want at least one issue", resp.Issues)
	}
	issue := resp.Issues[0]
	if issue.Scope != scope || issue.Field != field || issue.Message != message {
		t.Fatalf("first issue = %#v, want scope=%q field=%q message=%q", issue, scope, field, message)
	}
	if resp.Error != summarizeRuleIssues(resp.Issues) {
		t.Fatalf("error = %q, want %q", resp.Error, summarizeRuleIssues(resp.Issues))
	}
}

func TestHandleAddSiteValidationErrorIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/sites", Site{})
	w := httptest.NewRecorder()

	handleAddSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "site", "domain and backend_ip are required")
}

func TestHandleToggleRuleNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/rules/toggle?id=404", nil)
	w := httptest.NewRecorder()

	handleToggleRule(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "toggle", "id", "rule not found")
}

func TestHandleToggleRuleInvalidIDIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/rules/toggle?id=bad", nil)
	w := httptest.NewRecorder()

	handleToggleRule(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "toggle", "id", "invalid id")
}

func TestHandleValidateRulesEmptyBatchIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/rules/validate", ruleBatchRequest{})
	w := httptest.NewRecorder()

	handleValidateRules(w, req, db)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp ruleValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Valid {
		t.Fatalf("valid = true, want false body=%s", w.Body.String())
	}
	assertValidationIssue(t, validationErrorResponse{
		Error:  resp.Error,
		Issues: resp.Issues,
	}, "request", "", "at least one batch operation is required")
}

func TestHandleBatchRulesEmptyBatchIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/rules/batch", ruleBatchRequest{})
	w := httptest.NewRecorder()

	handleBatchRules(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp ruleValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if resp.Valid {
		t.Fatalf("valid = true, want false body=%s", w.Body.String())
	}
	assertValidationIssue(t, validationErrorResponse{
		Error:  resp.Error,
		Issues: resp.Issues,
	}, "request", "", "at least one batch operation is required")
}

func TestHandleDeleteRuleNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/rules?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteRule(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "rule not found")
}

func TestHandleUpdateSiteNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPut, "/api/sites", Site{
		ID:          404,
		Domain:      "example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.10",
		BackendHTTP: 8080,
	})
	w := httptest.NewRecorder()

	handleUpdateSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "update", "id", "site not found")
}

func TestHandleToggleSiteNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/sites/toggle?id=404", nil)
	w := httptest.NewRecorder()

	handleToggleSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "toggle", "id", "site not found")
}

func TestHandleDeleteSiteNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/sites?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "site not found")
}

func TestHandleDeleteSiteInvalidIDIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/sites?id=bad", nil)
	w := httptest.NewRecorder()

	handleDeleteSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "invalid id")
}

func TestHandleAddRangeValidationErrorIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/ranges", PortRange{})
	w := httptest.NewRecorder()

	handleAddRange(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "create", "range", "in_ip, start_port, end_port, out_ip are required")
}

func TestHandleUpdateRangeNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPut, "/api/ranges", PortRange{
		ID:           404,
		InIP:         "0.0.0.0",
		StartPort:    10000,
		EndPort:      10000,
		OutIP:        "192.0.2.20",
		OutStartPort: 10000,
		Protocol:     "tcp",
	})
	w := httptest.NewRecorder()

	handleUpdateRange(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "update", "id", "range not found")
}

func TestHandleToggleRangeNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodPost, "/api/ranges/toggle?id=404", nil)
	w := httptest.NewRecorder()

	handleToggleRange(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "toggle", "id", "range not found")
}

func TestHandleDeleteRangeNotFoundIncludesIssues(t *testing.T) {
	db := openTestDB(t)
	req := newJSONRequest(t, http.MethodDelete, "/api/ranges?id=404", nil)
	w := httptest.NewRecorder()

	handleDeleteRange(w, req, db, &ProcessManager{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}

	resp := decodeValidationResponse(t, w)
	assertValidationIssue(t, resp, "delete", "id", "range not found")
}

func TestHandleAddSiteRejectsUnknownJSONField(t *testing.T) {
	db := openTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/sites", bytes.NewBufferString(`{"domain":"example.com","listen_ip":"0.0.0.0","backend_ip":"192.0.2.10","backend_http":8080,"unexpected":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddSite(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeErrorResponse(t, w)
	if resp["error"] != "invalid request body" {
		t.Fatalf("error = %q, want %q", resp["error"], "invalid request body")
	}
}

func TestHandleAddIPv6AssignmentRejectsTrailingJSONPayload(t *testing.T) {
	db := openTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/ipv6-assignments", bytes.NewBufferString(`{"parent_interface":"vmbr0"}{"target_interface":"tap100i0"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleAddIPv6Assignment(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeErrorResponse(t, w)
	if resp["error"] != "invalid request body" {
		t.Fatalf("error = %q, want %q", resp["error"], "invalid request body")
	}
}

func TestHandleBatchRulesRejectsOversizedJSONBody(t *testing.T) {
	db := openTestDB(t)
	payload := `{"create":[{"in_ip":"0.0.0.0","in_port":10000,"out_ip":"192.0.2.10","out_port":10000,"protocol":"tcp","remark":"` +
		strings.Repeat("x", int(apiJSONBatchBodyMaxBytes)) +
		`"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules/batch", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleBatchRules(w, req, db, &ProcessManager{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	resp := decodeErrorResponse(t, w)
	if resp["error"] != "invalid request body" {
		t.Fatalf("error = %q, want %q", resp["error"], "invalid request body")
	}
}
