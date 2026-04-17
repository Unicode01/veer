package store

import "strings"

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
	return item, err
}

func AddManagedNetwork(db RuleStore, item *ManagedNetwork) (int64, error) {
	stored := *item
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

func UpdateManagedNetwork(db RuleStore, item *ManagedNetwork) error {
	stored := *item
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

func DeleteManagedNetwork(db RuleStore, id int64) error {
	if err := DeleteManagedNetworkReservationsByManagedNetworkID(db, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM managed_networks WHERE id = ?`, id)
	return err
}

func GetManagedNetworks(db RuleStore) ([]ManagedNetwork, error) {
	return queryManagedNetworks(db, `SELECT `+managedNetworkColumns+` FROM managed_networks`)
}

func GetEnabledManagedNetworks(db RuleStore) ([]ManagedNetwork, error) {
	return queryManagedNetworks(db, `SELECT `+managedNetworkColumns+` FROM managed_networks WHERE enabled = 1`)
}

func GetManagedNetworksByIDs(db RuleStore, ids []int64) ([]ManagedNetwork, error) {
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
	return queryManagedNetworks(db, query, args...)
}

func queryManagedNetworks(db RuleStore, query string, args ...interface{}) ([]ManagedNetwork, error) {
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

func GetManagedNetwork(db RuleStore, id int64) (*ManagedNetwork, error) {
	item, err := scanManagedNetwork(db.QueryRow(`SELECT `+managedNetworkColumns+` FROM managed_networks WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func SetManagedNetworkEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE managed_networks SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
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

func AddManagedNetworkReservation(db RuleStore, item *ManagedNetworkReservation) (int64, error) {
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

func UpdateManagedNetworkReservation(db RuleStore, item *ManagedNetworkReservation) error {
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

func DeleteManagedNetworkReservation(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM managed_network_reservations WHERE id = ?`, id)
	return err
}

func DeleteManagedNetworkReservationsByManagedNetworkID(db RuleStore, managedNetworkID int64) error {
	_, err := db.Exec(`DELETE FROM managed_network_reservations WHERE managed_network_id = ?`, managedNetworkID)
	return err
}

func GetManagedNetworkReservations(db RuleStore) ([]ManagedNetworkReservation, error) {
	return queryManagedNetworkReservations(db, `SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations`)
}

func GetManagedNetworkReservationsByManagedNetworkIDs(db RuleStore, managedNetworkIDs []int64) ([]ManagedNetworkReservation, error) {
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
	return queryManagedNetworkReservations(db, query, args...)
}

func queryManagedNetworkReservations(db RuleStore, query string, args ...interface{}) ([]ManagedNetworkReservation, error) {
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

func GetManagedNetworkReservationCounts(db RuleStore) (map[int64]int, error) {
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

func GetManagedNetworkReservationsByManagedNetworkID(db RuleStore, managedNetworkID int64) ([]ManagedNetworkReservation, error) {
	return queryManagedNetworkReservations(db, `SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations WHERE managed_network_id = ?`, managedNetworkID)
}

func GetManagedNetworkReservation(db RuleStore, id int64) (*ManagedNetworkReservation, error) {
	item, err := scanManagedNetworkReservation(db.QueryRow(`SELECT `+managedNetworkReservationColumns+` FROM managed_network_reservations WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}
