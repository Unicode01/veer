package store

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

const (
	dbBusyTimeoutMillis  = 5000
	dbTxLockMode         = "immediate"
	dbByIDQueryChunkSize = 500
)

type IndexDefinition struct {
	Name    string
	Table   string
	Columns string
}

type ConstraintIndexDefinition struct {
	Name           string
	CreateSQL      string
	DuplicateProbe string
}

type RuleStore interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// 期望的表结构: table -> []{ column, type_and_default }
// 启动时自动对比实际表结构，缺少的列自动 ALTER TABLE ADD COLUMN
var Schema = map[string][][2]string{
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

var SchemaIndexes = []IndexDefinition{
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
	ConstraintIndexSitesHTTPDomainEnabled               = "ux_sites_http_domain_enabled"
	ConstraintIndexSitesHTTPSDomainEnabled              = "ux_sites_https_domain_enabled"
	ConstraintIndexManagedNetworkReservationNetworkMAC  = "ux_managed_network_reservations_network_mac"
	ConstraintIndexManagedNetworkReservationNetworkIPv4 = "ux_managed_network_reservations_network_ipv4"
)

var SchemaConstraintIndexes = []ConstraintIndexDefinition{
	{
		Name:      ConstraintIndexSitesHTTPDomainEnabled,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + ConstraintIndexSitesHTTPDomainEnabled + ` ON sites((CASE WHEN enabled = 1 AND backend_http > 0 AND trim(domain) <> '' THEN lower(trim(domain)) END))`,
		DuplicateProbe: `SELECT lower(trim(domain))
			FROM sites
			WHERE enabled = 1 AND backend_http > 0 AND trim(domain) <> ''
			GROUP BY lower(trim(domain))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      ConstraintIndexSitesHTTPSDomainEnabled,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + ConstraintIndexSitesHTTPSDomainEnabled + ` ON sites((CASE WHEN enabled = 1 AND backend_https > 0 AND trim(domain) <> '' THEN lower(trim(domain)) END))`,
		DuplicateProbe: `SELECT lower(trim(domain))
			FROM sites
			WHERE enabled = 1 AND backend_https > 0 AND trim(domain) <> ''
			GROUP BY lower(trim(domain))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      ConstraintIndexManagedNetworkReservationNetworkMAC,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + ConstraintIndexManagedNetworkReservationNetworkMAC + ` ON managed_network_reservations(managed_network_id, (CASE WHEN trim(mac_address) <> '' THEN lower(trim(mac_address)) END)) WHERE managed_network_id > 0 AND trim(mac_address) <> ''`,
		DuplicateProbe: `SELECT printf('%d:%s', managed_network_id, lower(trim(mac_address)))
			FROM managed_network_reservations
			WHERE managed_network_id > 0 AND trim(mac_address) <> ''
			GROUP BY managed_network_id, lower(trim(mac_address))
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
	{
		Name:      ConstraintIndexManagedNetworkReservationNetworkIPv4,
		CreateSQL: `CREATE UNIQUE INDEX IF NOT EXISTS ` + ConstraintIndexManagedNetworkReservationNetworkIPv4 + ` ON managed_network_reservations(managed_network_id, (CASE WHEN trim(ipv4_address) <> '' THEN trim(ipv4_address) END)) WHERE managed_network_id > 0 AND trim(ipv4_address) <> ''`,
		DuplicateProbe: `SELECT printf('%d:%s', managed_network_id, trim(ipv4_address))
			FROM managed_network_reservations
			WHERE managed_network_id > 0 AND trim(ipv4_address) <> ''
			GROUP BY managed_network_id, trim(ipv4_address)
			HAVING COUNT(*) > 1
			LIMIT 1`,
	},
}

func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_txlock=%s", path, dbBusyTimeoutMillis, dbTxLockMode))
	if err != nil {
		return nil, err
	}

	for table, cols := range Schema {
		if err := EnsureTable(db, table, cols); err != nil {
			return nil, fmt.Errorf("migrate table %s: %w", table, err)
		}
	}
	if err := EnsureIndexes(db, SchemaIndexes); err != nil {
		return nil, fmt.Errorf("migrate indexes: %w", err)
	}
	if err := EnsureConstraintIndexes(db, SchemaConstraintIndexes); err != nil {
		return nil, fmt.Errorf("migrate constraint indexes: %w", err)
	}

	return db, nil
}

// ensureTable 创建表（如不存在），然后对比已有列，补齐缺失列
func EnsureTable(db *sql.DB, table string, columns [][2]string) error {
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

func EnsureIndexes(db *sql.DB, indexes []IndexDefinition) error {
	for _, index := range indexes {
		if err := EnsureIndex(db, index); err != nil {
			return err
		}
	}
	return nil
}

func EnsureIndex(db *sql.DB, index IndexDefinition) error {
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

func EnsureConstraintIndexes(db *sql.DB, indexes []ConstraintIndexDefinition) error {
	for _, index := range indexes {
		if err := EnsureConstraintIndex(db, index); err != nil {
			return err
		}
	}
	return nil
}

func EnsureConstraintIndex(db *sql.DB, index ConstraintIndexDefinition) error {
	exists, err := DBIndexExists(db, index.Name)
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

func DBIndexExists(db *sql.DB, name string) (bool, error) {
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

func SQLiteUniqueConstraintIndexName(err error) string {
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func QueryProtocolMapByIDs(db RuleStore, queryFmt string, ids []int64, normalize func(string) string) (map[int64]string, error) {
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
