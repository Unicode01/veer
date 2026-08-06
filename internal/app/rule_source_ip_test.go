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

func TestSiteQUICPersistsInDB(t *testing.T) {
	db := openTestDB(t)
	input := Site{
		Domain:       "quic.example.test",
		ListenIP:     "0.0.0.0",
		BackendIP:    "192.0.2.10",
		BackendHTTPS: 9443,
		QUIC:         true,
		Enabled:      true,
	}
	id, err := dbAddSite(db, &input)
	if err != nil {
		t.Fatalf("add site: %v", err)
	}
	got, err := dbGetSite(db, id)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	if !got.QUIC {
		t.Fatal("site QUIC = false, want true")
	}

	got.QUIC = false
	if err := dbUpdateSite(db, got); err != nil {
		t.Fatalf("update site: %v", err)
	}
	updated, err := dbGetSite(db, id)
	if err != nil {
		t.Fatalf("get updated site: %v", err)
	}
	if updated.QUIC {
		t.Fatal("updated site QUIC = true, want false")
	}
}

func TestInitDBMigratesSiteQUICDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-forward.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL DEFAULT '',
		listen_ip TEXT NOT NULL DEFAULT '0.0.0.0',
		listen_iface TEXT NOT NULL DEFAULT '',
		backend_ip TEXT NOT NULL DEFAULT '',
		backend_source_ip TEXT NOT NULL DEFAULT '',
		backend_http INTEGER NOT NULL DEFAULT 0,
		backend_https INTEGER NOT NULL DEFAULT 0,
		tag TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		transparent INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		legacy.Close()
		t.Fatalf("create legacy sites table: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO sites (domain, backend_ip, backend_https) VALUES ('legacy.example.test', '192.0.2.10', 443)`); err != nil {
		legacy.Close()
		t.Fatalf("insert legacy site: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	db, err := initDB(path)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer db.Close()
	site, err := dbGetSite(db, 1)
	if err != nil {
		t.Fatalf("get migrated site: %v", err)
	}
	if site.QUIC {
		t.Fatal("migrated site QUIC = true, want default false")
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

func TestRuleEnginePreferencePersistsInDB(t *testing.T) {
	db := openTestDB(t)

	input := Rule{
		InIP:             "198.51.100.3",
		InPort:           30022,
		OutInterface:     "eth0",
		OutIP:            "203.0.113.30",
		OutPort:          22,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineUserspace,
	}
	id, err := dbAddRule(db, &input)
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	got, err := dbGetRule(db, id)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if got.EnginePreference != ruleEngineUserspace {
		t.Fatalf("engine preference mismatch after add: got %q want %q", got.EnginePreference, ruleEngineUserspace)
	}

	got.EnginePreference = ruleEngineKernel
	if err := dbUpdateRule(db, got); err != nil {
		t.Fatalf("update rule: %v", err)
	}

	updated, err := dbGetRule(db, id)
	if err != nil {
		t.Fatalf("get updated rule: %v", err)
	}
	if updated.EnginePreference != ruleEngineKernel {
		t.Fatalf("engine preference mismatch after update: got %q want %q", updated.EnginePreference, ruleEngineKernel)
	}
}
