package app

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const ruleColumns = `id, in_interface, in_ip, in_port, out_interface, out_ip, out_source_ip, out_port, protocol, remark, tag, enabled, transparent, engine_preference`

const (
	dbBusyTimeoutMillis  = 5000
	dbTxLockMode         = "immediate"
	dbByIDQueryChunkSize = 500
)

type dbIndexDefinition struct {
	Name    string
	Table   string
	Columns string
}

type dbConstraintIndexDefinition struct {
	Name           string
	CreateSQL      string
	DuplicateProbe string
}

type sqlRuleStore interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

func scanRule(sc interface{ Scan(...interface{}) error }) (Rule, error) {
	var r Rule
	var enginePreference string
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.InPort, &r.OutInterface, &r.OutIP, &r.OutSourceIP, &r.OutPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent, &enginePreference)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	r.EnginePreference = normalizeRuleEnginePreference(enginePreference)
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
		{"out_source_ip", "TEXT NOT NULL DEFAULT ''"},
		{"out_port", "INTEGER NOT NULL DEFAULT 0"},
		{"protocol", "TEXT NOT NULL DEFAULT 'tcp'"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"tag", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"transparent", "INTEGER NOT NULL DEFAULT 0"},
		{"engine_preference", "TEXT NOT NULL DEFAULT 'auto'"},
	},
	"sites": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"domain", "TEXT NOT NULL DEFAULT ''"},
		{"listen_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'"},
		{"listen_iface", "TEXT NOT NULL DEFAULT ''"},
		{"backend_ip", "TEXT NOT NULL DEFAULT ''"},
		{"backend_source_ip", "TEXT NOT NULL DEFAULT ''"},
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
		{"out_source_ip", "TEXT NOT NULL DEFAULT ''"},
		{"out_start_port", "INTEGER NOT NULL DEFAULT 0"},
		{"protocol", "TEXT NOT NULL DEFAULT 'tcp'"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"tag", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"transparent", "INTEGER NOT NULL DEFAULT 0"},
	},
	"egress_nats": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"parent_interface", "TEXT NOT NULL DEFAULT ''"},
		{"child_interface", "TEXT NOT NULL DEFAULT ''"},
		{"out_interface", "TEXT NOT NULL DEFAULT ''"},
		{"out_source_ip", "TEXT NOT NULL DEFAULT ''"},
		{"protocol", "TEXT NOT NULL DEFAULT 'tcp+udp'"},
		{"nat_type", "TEXT NOT NULL DEFAULT 'symmetric'"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
	},
	"ipv6_assignments": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"parent_interface", "TEXT NOT NULL DEFAULT ''"},
		{"target_interface", "TEXT NOT NULL DEFAULT ''"},
		{"parent_prefix", "TEXT NOT NULL DEFAULT ''"},
		{"assigned_prefix", "TEXT NOT NULL DEFAULT ''"},
		{"address", "TEXT NOT NULL DEFAULT ''"},
		{"prefix_len", "INTEGER NOT NULL DEFAULT 128"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
	},
	"managed_networks": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"name", "TEXT NOT NULL DEFAULT ''"},
		{"bridge_mode", "TEXT NOT NULL DEFAULT 'create'"},
		{"bridge", "TEXT NOT NULL DEFAULT ''"},
		{"bridge_mtu", "INTEGER NOT NULL DEFAULT 0"},
		{"bridge_vlan_aware", "INTEGER NOT NULL DEFAULT 0"},
		{"uplink_interface", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"ipv4_cidr", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_gateway", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_pool_start", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_pool_end", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_dns_servers", "TEXT NOT NULL DEFAULT ''"},
		{"ipv6_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"ipv6_parent_interface", "TEXT NOT NULL DEFAULT ''"},
		{"ipv6_parent_prefix", "TEXT NOT NULL DEFAULT ''"},
		{"ipv6_assignment_mode", "TEXT NOT NULL DEFAULT 'single_128'"},
		{"auto_egress_nat", "INTEGER NOT NULL DEFAULT 0"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
		{"enabled", "INTEGER NOT NULL DEFAULT 1"},
	},
	"managed_network_reservations": {
		{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{"managed_network_id", "INTEGER NOT NULL DEFAULT 0"},
		{"mac_address", "TEXT NOT NULL DEFAULT ''"},
		{"ipv4_address", "TEXT NOT NULL DEFAULT ''"},
		{"remark", "TEXT NOT NULL DEFAULT ''"},
	},
}

var schemaIndexes = []dbIndexDefinition{
	{Name: "idx_rules_enabled", Table: "rules", Columns: "enabled"},
	{Name: "idx_rules_tag", Table: "rules", Columns: "tag"},
	{Name: "idx_rules_protocol", Table: "rules", Columns: "protocol"},
	{Name: "idx_rules_listener", Table: "rules", Columns: "in_interface, in_ip, in_port, protocol, enabled"},
	{Name: "idx_rules_target", Table: "rules", Columns: "out_interface, out_ip, out_port, enabled"},
	{Name: "idx_sites_enabled", Table: "sites", Columns: "enabled"},
	{Name: "idx_sites_domain", Table: "sites", Columns: "domain"},
	{Name: "idx_sites_listener", Table: "sites", Columns: "listen_iface, listen_ip, enabled"},
	{Name: "idx_ranges_enabled", Table: "ranges", Columns: "enabled"},
	{Name: "idx_ranges_tag", Table: "ranges", Columns: "tag"},
	{Name: "idx_ranges_protocol", Table: "ranges", Columns: "protocol"},
	{Name: "idx_ranges_listener", Table: "ranges", Columns: "in_interface, in_ip, start_port, end_port, enabled"},
	{Name: "idx_egress_nats_enabled", Table: "egress_nats", Columns: "enabled"},
	{Name: "idx_egress_nats_scope", Table: "egress_nats", Columns: "parent_interface, child_interface, out_interface, enabled"},
	{Name: "idx_managed_networks_enabled", Table: "managed_networks", Columns: "enabled"},
	{Name: "idx_managed_network_reservations_network_id", Table: "managed_network_reservations", Columns: "managed_network_id"},
	{Name: "idx_ipv6_assignments_enabled", Table: "ipv6_assignments", Columns: "enabled"},
}

const (
	dbConstraintIndexSitesHTTPDomainEnabled               = "ux_sites_http_domain_enabled"
	dbConstraintIndexSitesHTTPSDomainEnabled              = "ux_sites_https_domain_enabled"
	dbConstraintIndexManagedNetworkReservationNetworkMAC  = "ux_managed_network_reservations_network_mac"
	dbConstraintIndexManagedNetworkReservationNetworkIPv4 = "ux_managed_network_reservations_network_ipv4"
)

var schemaConstraintIndexes = []dbConstraintIndexDefinition{
	{
		Name:      dbConstraintIndexSitesHTTPDomainEnabled,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + dbConstraintIndexSitesHTTPDomainEnabled + ` ON sites((CASE WHEN enabled = 1 AND backend_http > 0 AND trim(domain) <> '' THEN lower(trim(domain)) END))`,
		DuplicateProbe: `SELECT lower(trim(domain))
			FROM sites
			WHERE enabled = 1 AND backend_http > 0 AND trim(domain) <> ''
			GROUP BY lower(trim(domain))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      dbConstraintIndexSitesHTTPSDomainEnabled,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + dbConstraintIndexSitesHTTPSDomainEnabled + ` ON sites((CASE WHEN enabled = 1 AND backend_https > 0 AND trim(domain) <> '' THEN lower(trim(domain)) END))`,
		DuplicateProbe: `SELECT lower(trim(domain))
			FROM sites
			WHERE enabled = 1 AND backend_https > 0 AND trim(domain) <> ''
			GROUP BY lower(trim(domain))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      dbConstraintIndexManagedNetworkReservationNetworkMAC,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + dbConstraintIndexManagedNetworkReservationNetworkMAC + ` ON managed_network_reservations(managed_network_id, (CASE WHEN trim(mac_address) <> '' THEN lower(trim(mac_address)) END)) WHERE managed_network_id > 0 AND trim(mac_address) <> ''`,
		DuplicateProbe: `SELECT printf('%d:%s', managed_network_id, lower(trim(mac_address)))
			FROM managed_network_reservations
			WHERE managed_network_id > 0 AND trim(mac_address) <> ''
			GROUP BY managed_network_id, lower(trim(mac_address))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      dbConstraintIndexManagedNetworkReservationNetworkIPv4,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + dbConstraintIndexManagedNetworkReservationNetworkIPv4 + ` ON managed_network_reservations(managed_network_id, (CASE WHEN trim(ipv4_address) <> '' THEN trim(ipv4_address) END)) WHERE managed_network_id > 0 AND trim(ipv4_address) <> ''`,
		DuplicateProbe: `SELECT printf('%d:%s', managed_network_id, trim(ipv4_address))
			FROM managed_network_reservations
			WHERE managed_network_id > 0 AND trim(ipv4_address) <> ''
			GROUP BY managed_network_id, trim(ipv4_address)
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
}

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_txlock=%s", path, dbBusyTimeoutMillis, dbTxLockMode))
	if err != nil {
		return nil, err
	}

	for table, cols := range schema {
		if err := ensureTable(db, table, cols); err != nil {
			return nil, fmt.Errorf("migrate table %s: %w", table, err)
		}
	}
	if err := ensureIndexes(db, schemaIndexes); err != nil {
		return nil, fmt.Errorf("migrate indexes: %w", err)
	}
	if err := ensureConstraintIndexes(db, schemaConstraintIndexes); err != nil {
		return nil, fmt.Errorf("migrate constraint indexes: %w", err)
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

func ensureIndexes(db *sql.DB, indexes []dbIndexDefinition) error {
	for _, index := range indexes {
		if err := ensureIndex(db, index); err != nil {
			return err
		}
	}
	return nil
}

func ensureIndex(db *sql.DB, index dbIndexDefinition) error {
	var existing string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, index.Name).Scan(&existing)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	createSQL := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s)", index.Name, index.Table, index.Columns)
	if _, err := db.Exec(createSQL); err != nil {
		return fmt.Errorf("create index %s: %w", index.Name, err)
	}
	log.Printf("db migrate: added index %s on %s", index.Name, index.Table)
	return nil
}

func ensureConstraintIndexes(db *sql.DB, indexes []dbConstraintIndexDefinition) error {
	for _, index := range indexes {
		if err := ensureConstraintIndex(db, index); err != nil {
			return err
		}
	}
	return nil
}

func ensureConstraintIndex(db *sql.DB, index dbConstraintIndexDefinition) error {
	exists, err := dbIndexExists(db, index.Name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	if index.DuplicateProbe != "" {
		var sample string
		err := db.QueryRow(index.DuplicateProbe).Scan(&sample)
		switch {
		case err == nil:
			log.Printf("db migrate: skipped unique index %s due to existing duplicate value %q", index.Name, sample)
			return nil
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
	}

	if _, err := db.Exec(index.CreateSQL); err != nil {
		return fmt.Errorf("create unique index %s: %w", index.Name, err)
	}
	log.Printf("db migrate: added unique index %s", index.Name)
	return nil
}

func dbIndexExists(db *sql.DB, name string) (bool, error) {
	var existing string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&existing)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

type sqliteErrorCoder interface {
	Code() int
}

func sqliteUniqueConstraintIndexName(err error) string {
	var coder sqliteErrorCoder
	if !errors.As(err, &coder) || coder.Code() != sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		return ""
	}

	msg := err.Error()
	const marker = "index '"
	start := strings.Index(msg, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.Index(msg[start:], "'")
	if end < 0 {
		return ""
	}
	return msg[start : start+end]
}

func dbAddRule(db sqlRuleStore, r *Rule) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO rules (in_interface, in_ip, in_port, out_interface, out_ip, out_source_ip, out_port, protocol, remark, tag, enabled, transparent, engine_preference)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), normalizeRuleEnginePreference(r.EnginePreference),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateRule(db sqlRuleStore, r *Rule) error {
	_, err := db.Exec(
		`UPDATE rules SET in_interface=?, in_ip=?, in_port=?, out_interface=?, out_ip=?, out_source_ip=?, out_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=?, engine_preference=? WHERE id=?`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), normalizeRuleEnginePreference(r.EnginePreference), r.ID,
	)
	return err
}

func dbDeleteRule(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}

func dbGetRules(db sqlRuleStore) ([]Rule, error) {
	return dbQueryRules(db, `SELECT `+ruleColumns+` FROM rules`)
}

func dbGetEnabledRules(db sqlRuleStore) ([]Rule, error) {
	return dbQueryRules(db, `SELECT `+ruleColumns+` FROM rules WHERE enabled = 1`)
}

func dbGetRulesByIDs(db sqlRuleStore, ids []int64) ([]Rule, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return []Rule{}, nil
	}

	args := make([]interface{}, 0, len(normalized))
	holders := make([]string, 0, len(normalized))
	for _, id := range normalized {
		holders = append(holders, "?")
		args = append(args, id)
	}

	query := `SELECT ` + ruleColumns + ` FROM rules WHERE id IN (` + strings.Join(holders, ",") + `)`
	return dbQueryRules(db, query, args...)
}

func dbGetRulesFiltered(db sqlRuleStore, filters ruleFilter) ([]Rule, error) {
	query := `SELECT ` + ruleColumns + ` FROM rules`
	var where []string
	var args []interface{}

	appendInt64SetCondition(&where, &args, "id", filters.IDs)
	appendStringSetCondition(&where, &args, "tag", filters.Tags)
	appendLowerStringSetCondition(&where, &args, "protocol", filters.Protocols)
	if filters.Enabled != nil {
		where = append(where, "enabled = ?")
		args = append(args, boolToInt(*filters.Enabled))
	}
	if filters.Transparent != nil {
		where = append(where, "transparent = ?")
		args = append(args, boolToInt(*filters.Transparent))
	}
	appendExactStringCondition(&where, &args, "in_interface", filters.InInterface)
	appendExactStringCondition(&where, &args, "out_interface", filters.OutInterface)
	appendExactStringCondition(&where, &args, "in_ip", filters.InIP)
	appendExactStringCondition(&where, &args, "out_ip", filters.OutIP)
	appendExactStringCondition(&where, &args, "out_source_ip", filters.OutSourceIP)
	if filters.InPort > 0 {
		where = append(where, "in_port = ?")
		args = append(args, filters.InPort)
	}
	if filters.OutPort > 0 {
		where = append(where, "out_port = ?")
		args = append(args, filters.OutPort)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}

	return dbQueryRules(db, query, args...)
}

func dbGetEnabledRulesByIDs(db sqlRuleStore, ids []int64) ([]Rule, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return []Rule{}, nil
	}

	args := make([]interface{}, 0, len(normalized)+1)
	holders := make([]string, 0, len(normalized))
	for _, id := range normalized {
		holders = append(holders, "?")
		args = append(args, id)
	}

	query := `SELECT ` + ruleColumns + ` FROM rules WHERE enabled = 1 AND id IN (` + strings.Join(holders, ",") + `)`
	return dbQueryRules(db, query, args...)
}

func dbQueryRules(db sqlRuleStore, query string, args ...interface{}) ([]Rule, error) {
	rows, err := db.Query(query, args...)
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

func appendInt64SetCondition(where *[]string, args *[]interface{}, column string, values map[int64]struct{}) {
	if len(values) == 0 {
		return
	}

	items := make([]int64, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i] < items[j]
	})

	holders := make([]string, 0, len(items))
	for _, value := range items {
		holders = append(holders, "?")
		*args = append(*args, value)
	}
	*where = append(*where, fmt.Sprintf("%s IN (%s)", column, strings.Join(holders, ",")))
}

func appendStringSetCondition(where *[]string, args *[]interface{}, column string, values map[string]struct{}) {
	appendNormalizedStringSetCondition(where, args, column, values, false)
}

func appendLowerStringSetCondition(where *[]string, args *[]interface{}, column string, values map[string]struct{}) {
	appendNormalizedStringSetCondition(where, args, column, values, true)
}

func appendNormalizedStringSetCondition(where *[]string, args *[]interface{}, column string, values map[string]struct{}, lowerColumn bool) {
	if len(values) == 0 {
		return
	}

	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)

	holders := make([]string, 0, len(items))
	for _, value := range items {
		holders = append(holders, "?")
		*args = append(*args, value)
	}

	columnExpr := column
	if lowerColumn {
		columnExpr = "LOWER(" + column + ")"
	}
	*where = append(*where, fmt.Sprintf("%s IN (%s)", columnExpr, strings.Join(holders, ",")))
}

func appendExactStringCondition(where *[]string, args *[]interface{}, column, value string) {
	if value == "" {
		return
	}
	*where = append(*where, column+" = ?")
	*args = append(*args, value)
}

func normalizePositiveInt64Values(values []int64) []int64 {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func dbGetRule(db sqlRuleStore, id int64) (*Rule, error) {
	r, err := scanRule(db.QueryRow(`SELECT `+ruleColumns+` FROM rules WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func dbGetRuleMetaByIDs(db sqlRuleStore, ids []int64) (map[int64]Rule, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return map[int64]Rule{}, nil
	}

	result := make(map[int64]Rule, len(normalized))
	for start := 0; start < len(normalized); start += dbByIDQueryChunkSize {
		end := start + dbByIDQueryChunkSize
		if end > len(normalized) {
			end = len(normalized)
		}
		chunk := normalized[start:end]
		rows, err := db.Query(
			`SELECT id, protocol, remark FROM rules WHERE id IN (`+dbSQLPlaceholders(len(chunk))+`)`,
			dbInt64Args(chunk)...,
		)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var item Rule
			if err := rows.Scan(&item.ID, &item.Protocol, &item.Remark); err != nil {
				rows.Close()
				return nil, err
			}
			result[item.ID] = item
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return result, nil
}

func dbGetRuleProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	return dbQueryProtocolMapByIDs(db, `SELECT id, protocol FROM rules WHERE id IN (%s)`, ids, func(protocol string) string {
		return protocol
	})
}

func dbAddSite(db sqlRuleStore, s *Site) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO sites (domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Domain, s.ListenIP, s.ListenIface, s.BackendIP, s.BackendSourceIP, s.BackendHTTP, s.BackendHTTPS, s.Tag, boolToInt(s.Enabled), boolToInt(s.Transparent),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateSite(db sqlRuleStore, s *Site) error {
	_, err := db.Exec(
		`UPDATE sites SET domain=?, listen_ip=?, listen_iface=?, backend_ip=?, backend_source_ip=?, backend_http=?, backend_https=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		s.Domain, s.ListenIP, s.ListenIface, s.BackendIP, s.BackendSourceIP, s.BackendHTTP, s.BackendHTTPS, s.Tag, boolToInt(s.Enabled), boolToInt(s.Transparent), s.ID,
	)
	return err
}

func dbDeleteSite(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

func dbGetSites(db sqlRuleStore) ([]Site, error) {
	return dbQuerySites(db, `SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent FROM sites`)
}

func dbGetEnabledSites(db sqlRuleStore) ([]Site, error) {
	return dbQuerySites(db, `SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent FROM sites WHERE enabled = 1`)
}

func dbQuerySites(db sqlRuleStore, query string, args ...interface{}) ([]Site, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []Site
	for rows.Next() {
		var s Site
		var enabled, transparent int
		if err := rows.Scan(&s.ID, &s.Domain, &s.ListenIP, &s.ListenIface, &s.BackendIP, &s.BackendSourceIP, &s.BackendHTTP, &s.BackendHTTPS, &s.Tag, &enabled, &transparent); err != nil {
			return nil, err
		}
		s.Enabled = enabled != 0
		s.Transparent = transparent != 0
		sites = append(sites, s)
	}
	return sites, rows.Err()
}

func dbCountEnabledSites(db sqlRuleStore) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sites WHERE enabled = 1`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func dbGetSite(db sqlRuleStore, id int64) (*Site, error) {
	row := db.QueryRow(`SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent FROM sites WHERE id = ?`, id)
	var s Site
	var enabled, transparent int
	if err := row.Scan(&s.ID, &s.Domain, &s.ListenIP, &s.ListenIface, &s.BackendIP, &s.BackendSourceIP, &s.BackendHTTP, &s.BackendHTTPS, &s.Tag, &enabled, &transparent); err != nil {
		return nil, err
	}
	s.Enabled = enabled != 0
	s.Transparent = transparent != 0
	return &s, nil
}

const rangeColumns = `id, in_interface, in_ip, start_port, end_port, out_interface, out_ip, out_source_ip, out_start_port, protocol, remark, tag, enabled, transparent`

func scanPortRange(sc interface{ Scan(...interface{}) error }) (PortRange, error) {
	var r PortRange
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.StartPort, &r.EndPort, &r.OutInterface, &r.OutIP, &r.OutSourceIP, &r.OutStartPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	return r, err
}

func dbAddRange(db sqlRuleStore, r *PortRange) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO ranges (in_interface, in_ip, start_port, end_port, out_interface, out_ip, out_source_ip, out_start_port, protocol, remark, tag, enabled, transparent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InInterface, r.InIP, r.StartPort, r.EndPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutStartPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateRange(db sqlRuleStore, r *PortRange) error {
	_, err := db.Exec(
		`UPDATE ranges SET in_interface=?, in_ip=?, start_port=?, end_port=?, out_interface=?, out_ip=?, out_source_ip=?, out_start_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		r.InInterface, r.InIP, r.StartPort, r.EndPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutStartPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.ID,
	)
	return err
}

func dbDeleteRange(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM ranges WHERE id = ?`, id)
	return err
}

func dbGetRanges(db sqlRuleStore) ([]PortRange, error) {
	return dbQueryRanges(db, `SELECT `+rangeColumns+` FROM ranges`)
}

func dbGetEnabledRanges(db sqlRuleStore) ([]PortRange, error) {
	return dbQueryRanges(db, `SELECT `+rangeColumns+` FROM ranges WHERE enabled = 1`)
}

func dbGetEnabledRangesByIDs(db sqlRuleStore, ids []int64) ([]PortRange, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return []PortRange{}, nil
	}

	args := make([]interface{}, 0, len(normalized))
	holders := make([]string, 0, len(normalized))
	for _, id := range normalized {
		holders = append(holders, "?")
		args = append(args, id)
	}

	query := `SELECT ` + rangeColumns + ` FROM ranges WHERE enabled = 1 AND id IN (` + strings.Join(holders, ",") + `)`
	return dbQueryRanges(db, query, args...)
}

func dbQueryRanges(db sqlRuleStore, query string, args ...interface{}) ([]PortRange, error) {
	rows, err := db.Query(query, args...)
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

func dbGetRange(db sqlRuleStore, id int64) (*PortRange, error) {
	r, err := scanPortRange(db.QueryRow(`SELECT `+rangeColumns+` FROM ranges WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func dbGetRangeMetaByIDs(db sqlRuleStore, ids []int64) (map[int64]PortRange, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return map[int64]PortRange{}, nil
	}

	result := make(map[int64]PortRange, len(normalized))
	for start := 0; start < len(normalized); start += dbByIDQueryChunkSize {
		end := start + dbByIDQueryChunkSize
		if end > len(normalized) {
			end = len(normalized)
		}
		chunk := normalized[start:end]
		rows, err := db.Query(
			`SELECT id, protocol, remark FROM ranges WHERE id IN (`+dbSQLPlaceholders(len(chunk))+`)`,
			dbInt64Args(chunk)...,
		)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var item PortRange
			if err := rows.Scan(&item.ID, &item.Protocol, &item.Remark); err != nil {
				rows.Close()
				return nil, err
			}
			result[item.ID] = item
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return result, nil
}

func dbGetRangeProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	return dbQueryProtocolMapByIDs(db, `SELECT id, protocol FROM ranges WHERE id IN (%s)`, ids, func(protocol string) string {
		return protocol
	})
}

const egressNATColumns = `id, parent_interface, child_interface, out_interface, out_source_ip, protocol, nat_type, enabled`

func scanEgressNAT(sc interface{ Scan(...interface{}) error }) (EgressNAT, error) {
	var item EgressNAT
	var enabled int
	err := sc.Scan(&item.ID, &item.ParentInterface, &item.ChildInterface, &item.OutInterface, &item.OutSourceIP, &item.Protocol, &item.NATType, &enabled)
	item.Protocol = normalizeEgressNATProtocol(item.Protocol)
	item.NATType = normalizeEgressNATType(item.NATType)
	item.Enabled = enabled != 0
	return item, err
}

func dbAddEgressNAT(db sqlRuleStore, item *EgressNAT) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO egress_nats (parent_interface, child_interface, out_interface, out_source_ip, protocol, nat_type, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		item.ParentInterface, item.ChildInterface, item.OutInterface, item.OutSourceIP, normalizeEgressNATProtocol(item.Protocol), normalizeEgressNATType(item.NATType), boolToInt(item.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateEgressNAT(db sqlRuleStore, item *EgressNAT) error {
	_, err := db.Exec(
		`UPDATE egress_nats SET parent_interface=?, child_interface=?, out_interface=?, out_source_ip=?, protocol=?, nat_type=?, enabled=? WHERE id=?`,
		item.ParentInterface, item.ChildInterface, item.OutInterface, item.OutSourceIP, normalizeEgressNATProtocol(item.Protocol), normalizeEgressNATType(item.NATType), boolToInt(item.Enabled), item.ID,
	)
	return err
}

func dbDeleteEgressNAT(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM egress_nats WHERE id = ?`, id)
	return err
}

func dbGetEgressNATs(db sqlRuleStore) ([]EgressNAT, error) {
	return dbQueryEgressNATs(db, `SELECT `+egressNATColumns+` FROM egress_nats`)
}

func dbGetEnabledEgressNATs(db sqlRuleStore) ([]EgressNAT, error) {
	return dbQueryEgressNATs(db, `SELECT `+egressNATColumns+` FROM egress_nats WHERE enabled = 1`)
}

func dbGetEgressNATsByIDs(db sqlRuleStore, ids []int64) ([]EgressNAT, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return []EgressNAT{}, nil
	}

	items := make([]EgressNAT, 0, len(normalized))
	for start := 0; start < len(normalized); start += dbByIDQueryChunkSize {
		end := start + dbByIDQueryChunkSize
		if end > len(normalized) {
			end = len(normalized)
		}
		chunk := normalized[start:end]
		query := `SELECT ` + egressNATColumns + ` FROM egress_nats WHERE id IN (` + dbSQLPlaceholders(len(chunk)) + `)`
		chunkItems, err := dbQueryEgressNATs(db, query, dbInt64Args(chunk)...)
		if err != nil {
			return nil, err
		}
		items = append(items, chunkItems...)
	}
	return items, nil
}

func dbQueryEgressNATs(db sqlRuleStore, query string, args ...interface{}) ([]EgressNAT, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []EgressNAT
	for rows.Next() {
		item, err := scanEgressNAT(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func dbGetEgressNAT(db sqlRuleStore, id int64) (*EgressNAT, error) {
	item, err := scanEgressNAT(db.QueryRow(`SELECT `+egressNATColumns+` FROM egress_nats WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func dbGetEgressNATProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	return dbQueryProtocolMapByIDs(db, `SELECT id, protocol FROM egress_nats WHERE id IN (%s)`, ids, normalizeEgressNATProtocol)
}

func dbSetEgressNATEnabled(db sqlRuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE egress_nats SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dbSetRuleEnabled(db sqlRuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE rules SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func dbSetSiteEnabled(db sqlRuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE sites SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func dbSetRangeEnabled(db sqlRuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE ranges SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func dbSetManagedNetworkEnabled(db sqlRuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE managed_networks SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

const ipv6AssignmentColumns = `id, parent_interface, target_interface, parent_prefix, assigned_prefix, address, prefix_len, remark, enabled`

func scanIPv6Assignment(sc interface{ Scan(...interface{}) error }) (IPv6Assignment, error) {
	var item IPv6Assignment
	var enabled int
	err := sc.Scan(
		&item.ID,
		&item.ParentInterface,
		&item.TargetInterface,
		&item.ParentPrefix,
		&item.AssignedPrefix,
		&item.Address,
		&item.PrefixLen,
		&item.Remark,
		&enabled,
	)
	item.Enabled = enabled != 0
	hydrateIPv6AssignmentCompatibilityFields(&item)
	return item, err
}

func dbAddIPv6Assignment(db sqlRuleStore, item *IPv6Assignment) (int64, error) {
	stored := *item
	hydrateIPv6AssignmentCompatibilityFields(&stored)
	res, err := db.Exec(
		`INSERT INTO ipv6_assignments (parent_interface, target_interface, parent_prefix, assigned_prefix, address, prefix_len, remark, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		stored.ParentInterface,
		stored.TargetInterface,
		stored.ParentPrefix,
		stored.AssignedPrefix,
		stored.Address,
		stored.PrefixLen,
		stored.Remark,
		boolToInt(stored.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateIPv6Assignment(db sqlRuleStore, item *IPv6Assignment) error {
	stored := *item
	hydrateIPv6AssignmentCompatibilityFields(&stored)
	_, err := db.Exec(
		`UPDATE ipv6_assignments
		 SET parent_interface=?, target_interface=?, parent_prefix=?, assigned_prefix=?, address=?, prefix_len=?, remark=?, enabled=?
		 WHERE id=?`,
		stored.ParentInterface,
		stored.TargetInterface,
		stored.ParentPrefix,
		stored.AssignedPrefix,
		stored.Address,
		stored.PrefixLen,
		stored.Remark,
		boolToInt(stored.Enabled),
		stored.ID,
	)
	return err
}

func dbDeleteIPv6Assignment(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM ipv6_assignments WHERE id = ?`, id)
	return err
}

func dbGetIPv6Assignments(db sqlRuleStore) ([]IPv6Assignment, error) {
	return dbQueryIPv6Assignments(db, `SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments`)
}

func dbGetEnabledIPv6Assignments(db sqlRuleStore) ([]IPv6Assignment, error) {
	return dbQueryIPv6Assignments(db, `SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments WHERE enabled = 1`)
}

func dbQueryIPv6Assignments(db sqlRuleStore, query string, args ...interface{}) ([]IPv6Assignment, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []IPv6Assignment
	for rows.Next() {
		item, err := scanIPv6Assignment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func dbQueryProtocolMapByIDs(db sqlRuleStore, queryFmt string, ids []int64, normalize func(string) string) (map[int64]string, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return map[int64]string{}, nil
	}

	result := make(map[int64]string, len(normalized))
	for start := 0; start < len(normalized); start += dbByIDQueryChunkSize {
		end := start + dbByIDQueryChunkSize
		if end > len(normalized) {
			end = len(normalized)
		}
		chunk := normalized[start:end]
		rows, err := db.Query(fmt.Sprintf(queryFmt, dbSQLPlaceholders(len(chunk))), dbInt64Args(chunk)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				id       int64
				protocol string
			)
			if err := rows.Scan(&id, &protocol); err != nil {
				rows.Close()
				return nil, err
			}
			result[id] = normalize(protocol)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return result, nil
}

func dbInt64Args(values []int64) []interface{} {
	args := make([]interface{}, 0, len(values))
	for _, value := range values {
		args = append(args, value)
	}
	return args
}

func dbSQLPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	holders := make([]string, count)
	for i := range holders {
		holders[i] = "?"
	}
	return strings.Join(holders, ",")
}

func dbGetIPv6Assignment(db sqlRuleStore, id int64) (*IPv6Assignment, error) {
	item, err := scanIPv6Assignment(db.QueryRow(`SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

const managedNetworkColumns = `id, name, bridge_mode, bridge, bridge_mtu, bridge_vlan_aware, uplink_interface, ipv4_enabled, ipv4_cidr, ipv4_gateway, ipv4_pool_start, ipv4_pool_end, ipv4_dns_servers, ipv6_enabled, ipv6_parent_interface, ipv6_parent_prefix, ipv6_assignment_mode, auto_egress_nat, remark, enabled`

func scanManagedNetwork(sc interface{ Scan(...interface{}) error }) (ManagedNetwork, error) {
	var item ManagedNetwork
	var bridgeVLANAware, ipv4Enabled, ipv6Enabled, autoEgressNAT, enabled int
	err := sc.Scan(
		&item.ID,
		&item.Name,
		&item.BridgeMode,
		&item.Bridge,
		&item.BridgeMTU,
		&bridgeVLANAware,
		&item.UplinkInterface,
		&ipv4Enabled,
		&item.IPv4CIDR,
		&item.IPv4Gateway,
		&item.IPv4PoolStart,
		&item.IPv4PoolEnd,
		&item.IPv4DNSServers,
		&ipv6Enabled,
		&item.IPv6ParentInterface,
		&item.IPv6ParentPrefix,
		&item.IPv6AssignmentMode,
		&autoEgressNAT,
		&item.Remark,
		&enabled,
	)
	item.BridgeVLANAware = bridgeVLANAware != 0
	item.IPv4Enabled = ipv4Enabled != 0
	item.IPv6Enabled = ipv6Enabled != 0
	item.AutoEgressNAT = autoEgressNAT != 0
	item.Enabled = enabled != 0
	item = normalizeManagedNetwork(item)
	return item, err
}

func dbAddManagedNetwork(db sqlRuleStore, item *ManagedNetwork) (int64, error) {
	stored := normalizeManagedNetwork(*item)
	res, err := db.Exec(
		`INSERT INTO managed_networks (name, bridge_mode, bridge, bridge_mtu, bridge_vlan_aware, uplink_interface, ipv4_enabled, ipv4_cidr, ipv4_gateway, ipv4_pool_start, ipv4_pool_end, ipv4_dns_servers, ipv6_enabled, ipv6_parent_interface, ipv6_parent_prefix, ipv6_assignment_mode, auto_egress_nat, remark, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stored.Name,
		stored.BridgeMode,
		stored.Bridge,
		stored.BridgeMTU,
		boolToInt(stored.BridgeVLANAware),
		stored.UplinkInterface,
		boolToInt(stored.IPv4Enabled),
		stored.IPv4CIDR,
		stored.IPv4Gateway,
		stored.IPv4PoolStart,
		stored.IPv4PoolEnd,
		stored.IPv4DNSServers,
		boolToInt(stored.IPv6Enabled),
		stored.IPv6ParentInterface,
		stored.IPv6ParentPrefix,
		stored.IPv6AssignmentMode,
		boolToInt(stored.AutoEgressNAT),
		stored.Remark,
		boolToInt(stored.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateManagedNetwork(db sqlRuleStore, item *ManagedNetwork) error {
	stored := normalizeManagedNetwork(*item)
	_, err := db.Exec(
		`UPDATE managed_networks
		 SET name=?, bridge_mode=?, bridge=?, bridge_mtu=?, bridge_vlan_aware=?, uplink_interface=?, ipv4_enabled=?, ipv4_cidr=?, ipv4_gateway=?, ipv4_pool_start=?, ipv4_pool_end=?, ipv4_dns_servers=?, ipv6_enabled=?, ipv6_parent_interface=?, ipv6_parent_prefix=?, ipv6_assignment_mode=?, auto_egress_nat=?, remark=?, enabled=?
		 WHERE id=?`,
		stored.Name,
		stored.BridgeMode,
		stored.Bridge,
		stored.BridgeMTU,
		boolToInt(stored.BridgeVLANAware),
		stored.UplinkInterface,
		boolToInt(stored.IPv4Enabled),
		stored.IPv4CIDR,
		stored.IPv4Gateway,
		stored.IPv4PoolStart,
		stored.IPv4PoolEnd,
		stored.IPv4DNSServers,
		boolToInt(stored.IPv6Enabled),
		stored.IPv6ParentInterface,
		stored.IPv6ParentPrefix,
		stored.IPv6AssignmentMode,
		boolToInt(stored.AutoEgressNAT),
		stored.Remark,
		boolToInt(stored.Enabled),
		stored.ID,
	)
	return err
}

func dbDeleteManagedNetwork(db sqlRuleStore, id int64) error {
	if err := dbDeleteManagedNetworkReservationsByManagedNetworkID(db, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM managed_networks WHERE id = ?`, id)
	return err
}

func dbGetManagedNetworks(db sqlRuleStore) ([]ManagedNetwork, error) {
	return dbQueryManagedNetworks(db, `SELECT `+managedNetworkColumns+` FROM managed_networks`)
}

func dbGetEnabledManagedNetworks(db sqlRuleStore) ([]ManagedNetwork, error) {
	return dbQueryManagedNetworks(db, `SELECT `+managedNetworkColumns+` FROM managed_networks WHERE enabled = 1`)
}

func dbGetManagedNetworksByIDs(db sqlRuleStore, ids []int64) ([]ManagedNetwork, error) {
	normalized := normalizePositiveInt64Values(ids)
	if len(normalized) == 0 {
		return []ManagedNetwork{}, nil
	}

	args := make([]interface{}, 0, len(normalized))
	holders := make([]string, 0, len(normalized))
	for _, id := range normalized {
		args = append(args, id)
		holders = append(holders, "?")
	}

	query := `SELECT ` + managedNetworkColumns + ` FROM managed_networks WHERE id IN (` + strings.Join(holders, ",") + `)`
	return dbQueryManagedNetworks(db, query, args...)
}

func dbQueryManagedNetworks(db sqlRuleStore, query string, args ...interface{}) ([]ManagedNetwork, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ManagedNetwork
	for rows.Next() {
		item, err := scanManagedNetwork(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func dbGetManagedNetwork(db sqlRuleStore, id int64) (*ManagedNetwork, error) {
	item, err := scanManagedNetwork(db.QueryRow(`SELECT `+managedNetworkColumns+` FROM managed_networks WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

const managedNetworkReservationColumns = `id, managed_network_id, mac_address, ipv4_address, remark`

func scanManagedNetworkReservation(sc interface{ Scan(...interface{}) error }) (ManagedNetworkReservation, error) {
	var item ManagedNetworkReservation
	err := sc.Scan(
		&item.ID,
		&item.ManagedNetworkID,
		&item.MACAddress,
		&item.IPv4Address,
		&item.Remark,
	)
	return item, err
}

func dbAddManagedNetworkReservation(db sqlRuleStore, item *ManagedNetworkReservation) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO managed_network_reservations (managed_network_id, mac_address, ipv4_address, remark)
		 VALUES (?, ?, ?, ?)`,
		item.ManagedNetworkID,
		item.MACAddress,
		item.IPv4Address,
		item.Remark,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func dbUpdateManagedNetworkReservation(db sqlRuleStore, item *ManagedNetworkReservation) error {
	_, err := db.Exec(
		`UPDATE managed_network_reservations
		 SET managed_network_id=?, mac_address=?, ipv4_address=?, remark=?
		 WHERE id=?`,
		item.ManagedNetworkID,
		item.MACAddress,
		item.IPv4Address,
		item.Remark,
		item.ID,
	)
	return err
}

func dbDeleteManagedNetworkReservation(db sqlRuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM managed_network_reservations WHERE id = ?`, id)
	return err
}

func dbDeleteManagedNetworkReservationsByManagedNetworkID(db sqlRuleStore, managedNetworkID int64) error {
	_, err := db.Exec(`DELETE FROM managed_network_reservations WHERE managed_network_id = ?`, managedNetworkID)
	return err
}

func dbGetManagedNetworkReservations(db sqlRuleStore) ([]ManagedNetworkReservation, error) {
	return dbQueryManagedNetworkReservations(db, `SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations`)
}

func dbGetManagedNetworkReservationsByManagedNetworkIDs(db sqlRuleStore, managedNetworkIDs []int64) ([]ManagedNetworkReservation, error) {
	normalized := normalizePositiveInt64Values(managedNetworkIDs)
	if len(normalized) == 0 {
		return []ManagedNetworkReservation{}, nil
	}

	args := make([]interface{}, 0, len(normalized))
	holders := make([]string, 0, len(normalized))
	for _, managedNetworkID := range normalized {
		args = append(args, managedNetworkID)
		holders = append(holders, "?")
	}

	query := `SELECT ` + managedNetworkReservationColumns + ` FROM managed_network_reservations WHERE managed_network_id IN (` + strings.Join(holders, ",") + `)`
	return dbQueryManagedNetworkReservations(db, query, args...)
}

func dbQueryManagedNetworkReservations(db sqlRuleStore, query string, args ...interface{}) ([]ManagedNetworkReservation, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []ManagedNetworkReservation
	for rows.Next() {
		item, err := scanManagedNetworkReservation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func dbGetManagedNetworkReservationCounts(db sqlRuleStore) (map[int64]int, error) {
	rows, err := db.Query(`SELECT managed_network_id, COUNT(*) FROM managed_network_reservations WHERE managed_network_id > 0 GROUP BY managed_network_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out map[int64]int
	for rows.Next() {
		var managedNetworkID int64
		var count int
		if err := rows.Scan(&managedNetworkID, &count); err != nil {
			return nil, err
		}
		if managedNetworkID <= 0 {
			continue
		}
		if out == nil {
			out = make(map[int64]int)
		}
		out[managedNetworkID] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func dbGetManagedNetworkReservationsByManagedNetworkID(db sqlRuleStore, managedNetworkID int64) ([]ManagedNetworkReservation, error) {
	return dbQueryManagedNetworkReservations(db, `SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations WHERE managed_network_id = ?`, managedNetworkID)
}

func dbGetManagedNetworkReservation(db sqlRuleStore, id int64) (*ManagedNetworkReservation, error) {
	item, err := scanManagedNetworkReservation(db.QueryRow(`SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}
