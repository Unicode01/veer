package app

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openSchemaOnlyTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "forward-schema-only.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	for table, cols := range schema {
		if err := ensureTable(db, table, cols); err != nil {
			t.Fatalf("ensureTable(%s) error = %v", table, err)
		}
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	})
	return db
}

func TestInitDBCreatesConstraintIndexesOnCleanDatabase(t *testing.T) {
	db := openTestDB(t)

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'index'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()

	got := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		got[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index names: %v", err)
	}

	for _, index := range schemaConstraintIndexes {
		if _, ok := got[index.Name]; !ok {
			t.Fatalf("missing constraint index %q", index.Name)
		}
	}
}

func TestEnsureConstraintIndexesSkipsDirtyDuplicateData(t *testing.T) {
	db := openSchemaOnlyTestDB(t)

	if _, err := db.Exec(`INSERT INTO sites(domain, enabled, backend_http) VALUES ('Example.com', 1, 8080), ('example.com', 1, 8081)`); err != nil {
		t.Fatalf("seed duplicate sites: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO managed_network_reservations(managed_network_id, mac_address, ipv4_address) VALUES (1, 'AA:BB:CC:DD:EE:FF', '192.0.2.10'), (1, 'aa:bb:cc:dd:ee:ff', '192.0.2.11')`); err != nil {
		t.Fatalf("seed duplicate reservations: %v", err)
	}

	if err := ensureConstraintIndexes(db, schemaConstraintIndexes); err != nil {
		t.Fatalf("ensureConstraintIndexes() error = %v", err)
	}

	httpExists, err := dbIndexExists(db, dbConstraintIndexSitesHTTPDomainEnabled)
	if err != nil {
		t.Fatalf("dbIndexExists(http) error = %v", err)
	}
	if httpExists {
		t.Fatal("expected HTTP domain constraint index to be skipped")
	}
	macExists, err := dbIndexExists(db, dbConstraintIndexManagedNetworkReservationNetworkMAC)
	if err != nil {
		t.Fatalf("dbIndexExists(mac) error = %v", err)
	}
	if macExists {
		t.Fatal("expected reservation MAC constraint index to be skipped")
	}

	httpsExists, err := dbIndexExists(db, dbConstraintIndexSitesHTTPSDomainEnabled)
	if err != nil {
		t.Fatalf("dbIndexExists(https) error = %v", err)
	}
	if !httpsExists {
		t.Fatal("expected HTTPS domain constraint index to be created")
	}
	ipv4Exists, err := dbIndexExists(db, dbConstraintIndexManagedNetworkReservationNetworkIPv4)
	if err != nil {
		t.Fatalf("dbIndexExists(ipv4) error = %v", err)
	}
	if !ipv4Exists {
		t.Fatal("expected reservation IPv4 constraint index to be created")
	}
}

func TestSiteConstraintIssuesFromDBErrorMapsUniqueIndexConflict(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddSite(db, &Site{
		Domain:      "Example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.10",
		BackendHTTP: 8080,
		Enabled:     true,
	}); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("db.Begin() error = %v", err)
	}
	defer tx.Rollback()

	site := Site{
		Domain:      "example.com",
		ListenIP:    "0.0.0.0",
		BackendIP:   "192.0.2.11",
		BackendHTTP: 8081,
		Enabled:     true,
	}
	_, err = dbAddSite(tx, &site)
	if err == nil {
		t.Fatal("dbAddSite() error = nil, want unique constraint failure")
	}

	issues := siteConstraintIssuesFromDBError(tx, site, err, "create")
	if len(issues) != 1 {
		t.Fatalf("siteConstraintIssuesFromDBError() len = %d, want 1", len(issues))
	}
	if issues[0].Field != "domain" || issues[0].Message != "HTTP route conflicts with site #1 domain=example.com [HTTP]" {
		t.Fatalf("site constraint issue = %#v", issues[0])
	}
}

func TestManagedNetworkReservationConstraintIssuesFromDBErrorMapsUniqueIndexConflict(t *testing.T) {
	db := openTestDB(t)

	managedNetworkID, err := dbAddManagedNetwork(db, &ManagedNetwork{
		Name:        "lab",
		Bridge:      "vmbr0",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("dbAddManagedNetwork() error = %v", err)
	}
	if _, err := dbAddManagedNetworkReservation(db, &ManagedNetworkReservation{
		ManagedNetworkID: managedNetworkID,
		MACAddress:       "aa:bb:cc:dd:ee:ff",
		IPv4Address:      "192.0.2.10",
	}); err != nil {
		t.Fatalf("seed reservation: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("db.Begin() error = %v", err)
	}
	defer tx.Rollback()

	item := ManagedNetworkReservation{
		ManagedNetworkID: managedNetworkID,
		MACAddress:       "AA:BB:CC:DD:EE:FF",
		IPv4Address:      "192.0.2.11",
	}
	_, err = dbAddManagedNetworkReservation(tx, &item)
	if err == nil {
		t.Fatal("dbAddManagedNetworkReservation() error = nil, want unique constraint failure")
	}

	issues := managedNetworkReservationConstraintIssuesFromDBError(tx, item, err, "create")
	if len(issues) != 1 {
		t.Fatalf("managedNetworkReservationConstraintIssuesFromDBError() len = %d, want 1", len(issues))
	}
	if issues[0].Field != "mac_address" || issues[0].Message != "mac_address conflicts with reservation #1" {
		t.Fatalf("reservation constraint issue = %#v", issues[0])
	}
}
