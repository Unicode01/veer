package app

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dir := t.TempDir()
	db, err := initDB(filepath.Join(dir, "forward-test.db"))
	if err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	})
	return db
}

func TestRuleOutSourceIPPersistsInDB(t *testing.T) {
	db := openTestDB(t)

	input := Rule{
		InIP:         "198.51.100.1",
		InPort:       10022,
		OutInterface: "eth0",
		OutIP:        "203.0.113.10",
		OutSourceIP:  "203.0.113.1",
		OutPort:      22,
		Protocol:     "tcp",
		Remark:       "test",
		Enabled:      true,
	}
	id, err := dbAddRule(db, &input)
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	got, err := dbGetRule(db, id)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if got.OutSourceIP != input.OutSourceIP {
		t.Fatalf("out source ip mismatch: got %q want %q", got.OutSourceIP, input.OutSourceIP)
	}
}

func TestListRulesIncludesOutSourceIP(t *testing.T) {
	db := openTestDB(t)

	rule := Rule{
		InIP:        "198.51.100.2",
		InPort:      20022,
		OutIP:       "203.0.113.20",
		OutSourceIP: "203.0.113.2",
		OutPort:     22,
		Protocol:    "tcp",
		Enabled:     true,
	}
	if _, err := dbAddRule(db, &rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	pm := &ProcessManager{
		rulePlans:         map[int64]ruleDataplanePlan{},
		kernelRuleEngines: map[int64]string{},
		kernelRules:       map[int64]bool{},
	}
	req := httptest.NewRequest("GET", "/api/rules", nil)
	w := httptest.NewRecorder()

	handleListRules(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var got []RuleStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("unexpected rule count: %d", len(got))
	}
	if got[0].OutSourceIP != "203.0.113.2" {
		t.Fatalf("response out_source_ip mismatch: got %q", got[0].OutSourceIP)
	}
}
