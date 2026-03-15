package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "modernc.org/sqlite"
)

const ruleColumns = `id, in_interface, in_ip, in_port, out_interface, out_ip, out_port, protocol, remark, tag, enabled, transparent`

func scanRule(sc interface{ Scan(...interface{}) error }) (Rule, error) {
	var r Rule
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.InPort, &r.OutInterface, &r.OutIP, &r.OutPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	return r, err
}

// 期望的表结构: table -> []{ column, type_and_default }
// 启动时自动对比实际表结构，缺少的列自动 ALTER TABLE ADD COLUMN
var schema = map[string][][2]string{
	"rules": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"in_interface", "TEXT NOT NULL DEFAULT ''"},
		{"in_ip", "TEXT NOT NULL DEFAULT ''"},
		{"in_port", "INTEGER NOT NULL DEFAULT 0"},
		{"out_interface", "TEXT NOT NULL DEFAULT ''"},
		{"out_ip", "TEXT NOT NULL DEFAULT ''"},
		{"out_port", "INTEGER NOT NULL DEFAULT 0"},
		{"protocol", "TEXT NOT NULL DEFAULT 'tcp'"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"tag", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"transparent", "INTEGER NOT NULL DEFAULT 0"},
	},
	"sites": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"domain", "TEXT NOT NULL DEFAULT ''"},
		{"listen_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'"},
		{"listen_iface", "TEXT NOT NULL DEFAULT ''"},
		{"backend_ip", "TEXT NOT NULL DEFAULT ''"},
		{"backend_http", "INTEGER NOT NULL DEFAULT 0"},
		{"backend_https", "INTEGER NOT NULL DEFAULT 0"},
		{"tag", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"transparent", "INTEGER NOT NULL DEFAULT 0"},
	},
	"ranges": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"in_interface", "TEXT NOT NULL DEFAULT ''"},
		{"in_ip", "TEXT NOT NULL DEFAULT ''"},
		{"start_port", "INTEGER NOT NULL DEFAULT 0"},
		{"end_port", "INTEGER NOT NULL DEFAULT 0"},
		{"out_interface", "TEXT NOT NULL DEFAULT ''"},
		{"out_ip", "TEXT NOT NULL DEFAULT ''"},
		{"out_start_port", "INTEGER NOT NULL DEFAULT 0"},
		{"protocol", "TEXT NOT NULL DEFAULT 'tcp'"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"tag", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"transparent", "INTEGER NOT NULL DEFAULT 0"},
	},
}

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}

	for table, cols := range schema {
		if err := ensureTable(db, table, cols); err != nil {
			return nil, fmt.Errorf("migrate table %s: %w", table, err)
		}
	}

	return db, nil
}

// ensureTable 创建表（如不存在），然后对比已有列，补齐缺失列
func ensureTable(db *sql.DB, table string, columns [][2]string) error {
	// 用第一列构建最小 CREATE TABLE，确保表存在
	var colDefs []string
	for _, c := range columns {
		colDefs = append(colDefs, c[0]+" "+c[1])
	}
	createSQL := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", table, strings.Join(colDefs, ", "))
	if _, err := db.Exec(createSQL); err != nil {
		return err
	}

	// 查询已有列
	existing, err := getTableColumns(db, table)
	if err != nil {
		return err
	}

	// 补齐缺失列
	for _, c := range columns {
		name := c[0]
		if existing[name] {
			continue
		}
		alterSQL := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, name, c[1])
		if _, err := db.Exec(alterSQL); err != nil {
			return fmt.Errorf("add column %s.%s: %w", table, name, err)
		}
		log.Printf("db migrate: added column %s.%s", table, name)
	}

	return nil
}

// getTableColumns 通过 PRAGMA table_info 获取表的现有列名集合
func getTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func dbAddRule(db *sql.DB, r *Rule) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO rules (in_interface, in_ip, in_port, out_interface, out_ip, out_port, protocol, remark, tag, enabled, transparent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateRule(db *sql.DB, r *Rule) error {
	_, err := db.Exec(
		`UPDATE rules SET in_interface=?, in_ip=?, in_port=?, out_interface=?, out_ip=?, out_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.ID,
	)
	return err
}

func dbDeleteRule(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}

func dbGetRules(db *sql.DB) ([]Rule, error) {
	rows, err := db.Query(`SELECT ` + ruleColumns + ` FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func dbGetRule(db *sql.DB, id int64) (*Rule, error) {
	r, err := scanRule(db.QueryRow(`SELECT `+ruleColumns+` FROM rules WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func dbAddSite(db *sql.DB, s *Site) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO sites (domain, listen_ip, listen_iface, backend_ip, backend_http, backend_https, tag, enabled, transparent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Domain, s.ListenIP, s.ListenIface, s.BackendIP, s.BackendHTTP, s.BackendHTTPS, s.Tag, boolToInt(s.Enabled), boolToInt(s.Transparent),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateSite(db *sql.DB, s *Site) error {
	_, err := db.Exec(
		`UPDATE sites SET domain=?, listen_ip=?, listen_iface=?, backend_ip=?, backend_http=?, backend_https=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		s.Domain, s.ListenIP, s.ListenIface, s.BackendIP, s.BackendHTTP, s.BackendHTTPS, s.Tag, boolToInt(s.Enabled), boolToInt(s.Transparent), s.ID,
	)
	return err
}

func dbDeleteSite(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

func dbGetSites(db *sql.DB) ([]Site, error) {
	rows, err := db.Query(`SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_http, backend_https, tag, enabled, transparent FROM sites`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []Site
	for rows.Next() {
		var s Site
		var enabled, transparent int
		if err := rows.Scan(&s.ID, &s.Domain, &s.ListenIP, &s.ListenIface, &s.BackendIP, &s.BackendHTTP, &s.BackendHTTPS, &s.Tag, &enabled, &transparent); err != nil {
			return nil, err
		}
		s.Enabled = enabled != 0
		s.Transparent = transparent != 0
		sites = append(sites, s)
	}
	return sites, rows.Err()
}

func dbGetSite(db *sql.DB, id int64) (*Site, error) {
	row := db.QueryRow(`SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_http, backend_https, tag, enabled, transparent FROM sites WHERE id = ?`, id)
	var s Site
	var enabled, transparent int
	if err := row.Scan(&s.ID, &s.Domain, &s.ListenIP, &s.ListenIface, &s.BackendIP, &s.BackendHTTP, &s.BackendHTTPS, &s.Tag, &enabled, &transparent); err != nil {
		return nil, err
	}
	s.Enabled = enabled != 0
	s.Transparent = transparent != 0
	return &s, nil
}

const rangeColumns = `id, in_interface, in_ip, start_port, end_port, out_interface, out_ip, out_start_port, protocol, remark, tag, enabled, transparent`

func scanPortRange(sc interface{ Scan(...interface{}) error }) (PortRange, error) {
	var r PortRange
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.StartPort, &r.EndPort, &r.OutInterface, &r.OutIP, &r.OutStartPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	return r, err
}

func dbAddRange(db *sql.DB, r *PortRange) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO ranges (in_interface, in_ip, start_port, end_port, out_interface, out_ip, out_start_port, protocol, remark, tag, enabled, transparent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InInterface, r.InIP, r.StartPort, r.EndPort, r.OutInterface, r.OutIP, r.OutStartPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateRange(db *sql.DB, r *PortRange) error {
	_, err := db.Exec(
		`UPDATE ranges SET in_interface=?, in_ip=?, start_port=?, end_port=?, out_interface=?, out_ip=?, out_start_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		r.InInterface, r.InIP, r.StartPort, r.EndPort, r.OutInterface, r.OutIP, r.OutStartPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.ID,
	)
	return err
}

func dbDeleteRange(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM ranges WHERE id = ?`, id)
	return err
}

func dbGetRanges(db *sql.DB) ([]PortRange, error) {
	rows, err := db.Query(`SELECT ` + rangeColumns + ` FROM ranges`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ranges []PortRange
	for rows.Next() {
		r, err := scanPortRange(rows)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	return ranges, rows.Err()
}

func dbGetRange(db *sql.DB, id int64) (*PortRange, error) {
	r, err := scanPortRange(db.QueryRow(`SELECT `+rangeColumns+` FROM ranges WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dbSetRuleEnabled(db *sql.DB, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE rules SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func dbSetSiteEnabled(db *sql.DB, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE sites SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func dbSetRangeEnabled(db *sql.DB, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE ranges SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
