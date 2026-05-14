package store

import "fmt"

const wanProfileColumns = `id, name, type, parent_interface, runtime_interface, ipv4_cidr, ipv4_gateway, username, password, mtu, mru, default_route, metric, dns_mode, dns_servers, remark, enabled`

type WANProfileReferenceCounts struct {
	EgressNATs      int
	ManagedNetworks int
}

func scanWANProfile(sc interface{ Scan(...interface{}) error }) (WANProfile, error) {
	var item WANProfile
	var defaultRoute, enabled int
	err := sc.Scan(
		&item.ID,
		&item.Name,
		&item.Type,
		&item.ParentInterface,
		&item.RuntimeInterface,
		&item.IPv4CIDR,
		&item.IPv4Gateway,
		&item.Username,
		&item.Password,
		&item.MTU,
		&item.MRU,
		&defaultRoute,
		&item.Metric,
		&item.DNSMode,
		&item.DNSServers,
		&item.Remark,
		&enabled,
	)
	item.DefaultRoute = defaultRoute != 0
	item.Enabled = enabled != 0
	return item, err
}

func AddWANProfile(db RuleStore, item *WANProfile) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO wan_profiles (name, type, parent_interface, runtime_interface, ipv4_cidr, ipv4_gateway, username, password, mtu, mru, default_route, metric, dns_mode, dns_servers, remark, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.Name,
		item.Type,
		item.ParentInterface,
		item.RuntimeInterface,
		item.IPv4CIDR,
		item.IPv4Gateway,
		item.Username,
		item.Password,
		item.MTU,
		item.MRU,
		boolToInt(item.DefaultRoute),
		item.Metric,
		item.DNSMode,
		item.DNSServers,
		item.Remark,
		boolToInt(item.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateWANProfile(db RuleStore, item *WANProfile) error {
	_, err := db.Exec(
		`UPDATE wan_profiles
		 SET name=?, type=?, parent_interface=?, runtime_interface=?, ipv4_cidr=?, ipv4_gateway=?, username=?, password=?, mtu=?, mru=?, default_route=?, metric=?, dns_mode=?, dns_servers=?, remark=?, enabled=?
		 WHERE id=?`,
		item.Name,
		item.Type,
		item.ParentInterface,
		item.RuntimeInterface,
		item.IPv4CIDR,
		item.IPv4Gateway,
		item.Username,
		item.Password,
		item.MTU,
		item.MRU,
		boolToInt(item.DefaultRoute),
		item.Metric,
		item.DNSMode,
		item.DNSServers,
		item.Remark,
		boolToInt(item.Enabled),
		item.ID,
	)
	return err
}

func DeleteWANProfile(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM wan_profiles WHERE id = ?`, id)
	return err
}

func CountWANProfileReferences(db RuleStore, id int64) (WANProfileReferenceCounts, error) {
	var counts WANProfileReferenceCounts
	if err := db.QueryRow(`SELECT COUNT(*) FROM egress_nats WHERE wan_profile_id = ?`, id).Scan(&counts.EgressNATs); err != nil {
		return counts, fmt.Errorf("count egress nat references: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_networks WHERE wan_profile_id = ?`, id).Scan(&counts.ManagedNetworks); err != nil {
		return counts, fmt.Errorf("count managed network references: %w", err)
	}
	return counts, nil
}

func GetWANProfiles(db RuleStore) ([]WANProfile, error) {
	return queryWANProfiles(db, `SELECT `+wanProfileColumns+` FROM wan_profiles`)
}

func GetEnabledWANProfiles(db RuleStore) ([]WANProfile, error) {
	return queryWANProfiles(db, `SELECT `+wanProfileColumns+` FROM wan_profiles WHERE enabled = 1`)
}

func queryWANProfiles(db RuleStore, query string, args ...interface{}) ([]WANProfile, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []WANProfile
	for rows.Next() {
		item, err := scanWANProfile(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func GetWANProfile(db RuleStore, id int64) (*WANProfile, error) {
	item, err := scanWANProfile(db.QueryRow(`SELECT `+wanProfileColumns+` FROM wan_profiles WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func SetWANProfileEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE wan_profiles SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
