package app

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestPrepareRuleBatchRejectsConflictWithEnabledSite(t *testing.T) {
	db := openValidationTestDB(t)

	if _, err := dbAddSite(db, &Site{
		Domain:      "example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.10",
		BackendHTTP: 8080,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("dbAddSite() error = %v", err)
	}

	_, issues, err := prepareRuleBatch(db, ruleBatchRequest{
		Create: []Rule{{
			InIP:     "0.0.0.0",
			InPort:   80,
			OutIP:    "192.0.2.20",
			OutPort:  80,
			Protocol: "tcp",
		}},
	})
	if err != nil {
		t.Fatalf("prepareRuleBatch() error = %v", err)
	}
	if !hasValidationMessage(issues, "listener conflicts with site #1 * 0.0.0.0:80 [TCP] domain=example.com") {
		t.Fatalf("prepareRuleBatch() issues = %#v, want site listener conflict", issues)
	}
}

func TestPrepareSiteCreateRejectsConflictWithEnabledRange(t *testing.T) {
	db := openValidationTestDB(t)

	if _, err := dbAddRange(db, &PortRange{
		InIP:         "0.0.0.0",
		StartPort:    443,
		EndPort:      443,
		OutIP:        "192.0.2.30",
		OutStartPort: 8443,
		Protocol:     "tcp",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("dbAddRange() error = %v", err)
	}

	_, issues, err := prepareSiteCreate(db, Site{
		Domain:       "example.com",
		ListenIP:     "0.0.0.0",
		BackendIP:    "192.0.2.10",
		BackendHTTPS: 9443,
	})
	if err != nil {
		t.Fatalf("prepareSiteCreate() error = %v", err)
	}
	if !hasValidationMessage(issues, "listener conflicts with range #1 * 0.0.0.0:443-443 [TCP]") {
		t.Fatalf("prepareSiteCreate() issues = %#v, want range listener conflict", issues)
	}
}

func TestPrepareSiteCreateAllowsSharedListenerButRejectsDuplicateHTTPDomain(t *testing.T) {
	db := openValidationTestDB(t)

	if _, err := dbAddSite(db, &Site{
		Domain:      "example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.10",
		BackendHTTP: 8080,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("dbAddSite() error = %v", err)
	}

	if _, issues, err := prepareSiteCreate(db, Site{
		Domain:      "other.example",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.11",
		BackendHTTP: 8081,
	}); err != nil {
		t.Fatalf("prepareSiteCreate(shared) error = %v", err)
	} else if len(issues) != 0 {
		t.Fatalf("prepareSiteCreate(shared) issues = %#v, want no listener conflict for shared proxy listener", issues)
	}

	_, issues, err := prepareSiteCreate(db, Site{
		Domain:      "example.com",
		ListenIP:    "203.0.113.10",
		BackendIP:   "192.0.2.12",
		BackendHTTP: 8082,
	})
	if err != nil {
		t.Fatalf("prepareSiteCreate(duplicate domain) error = %v", err)
	}
	if !hasValidationMessage(issues, "HTTP route conflicts with site #1 domain=example.com [HTTP]") {
		t.Fatalf("prepareSiteCreate(duplicate domain) issues = %#v, want duplicate domain conflict", issues)
	}
}

func TestPrepareRangeToggleRejectsConflictWithEnabledRule(t *testing.T) {
	db := openValidationTestDB(t)

	if _, err := dbAddRule(db, &Rule{
		InIP:        "0.0.0.0",
		InPort:      20022,
		OutIP:       "192.0.2.20",
		OutPort:     22,
		Protocol:    "tcp",
		Enabled:     true,
		Transparent: false,
	}); err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}
	rangeID, err := dbAddRange(db, &PortRange{
		InIP:         "0.0.0.0",
		StartPort:    20022,
		EndPort:      20022,
		OutIP:        "192.0.2.21",
		OutStartPort: 2222,
		Protocol:     "tcp",
		Enabled:      false,
	})
	if err != nil {
		t.Fatalf("dbAddRange() error = %v", err)
	}

	_, issues, err := prepareRangeToggle(db, rangeID)
	if err != nil {
		t.Fatalf("prepareRangeToggle() error = %v", err)
	}
	if !hasValidationMessage(issues, "listener conflicts with rule #1 * 0.0.0.0:20022 [TCP]") {
		t.Fatalf("prepareRangeToggle() issues = %#v, want rule listener conflict", issues)
	}
}

func TestPrepareRuleBatchDeleteDisabledRuleStillDeletesExistingItem(t *testing.T) {
	db := openValidationTestDB(t)

	ruleID, err := dbAddRule(db, &Rule{
		InIP:     "0.0.0.0",
		InPort:   30022,
		OutIP:    "192.0.2.20",
		OutPort:  22,
		Protocol: "tcp",
		Enabled:  false,
	})
	if err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}

	prepared, issues, err := prepareRuleBatch(db, ruleBatchRequest{
		DeleteIDs: []int64{ruleID},
	})
	if err != nil {
		t.Fatalf("prepareRuleBatch() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("prepareRuleBatch() issues = %#v, want none", issues)
	}
	if len(prepared.DeleteIDs) != 1 || prepared.DeleteIDs[0] != ruleID {
		t.Fatalf("prepared.DeleteIDs = %#v, want [%d]", prepared.DeleteIDs, ruleID)
	}
}

func openValidationTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := initDB(filepath.Join(t.TempDir(), "forward-test.db"))
	if err != nil {
		t.Fatalf("initDB() error = %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}
