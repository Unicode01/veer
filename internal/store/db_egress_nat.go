package store

const egressNATColumns = `id, parent_interface, child_interface, out_interface, out_source_ip, protocol, nat_type, enabled`

func scanEgressNAT(sc interface{ Scan(...interface{}) error }) (EgressNAT, error) {
	var item EgressNAT
	var enabled int
	err := sc.Scan(&item.ID, &item.ParentInterface, &item.ChildInterface, &item.OutInterface, &item.OutSourceIP, &item.Protocol, &item.NATType, &enabled)
	item.Enabled = enabled != 0
	return item, err
}

func AddEgressNAT(db RuleStore, item *EgressNAT) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO egress_nats (parent_interface, child_interface, out_interface, out_source_ip, protocol, nat_type, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		item.ParentInterface, item.ChildInterface, item.OutInterface, item.OutSourceIP, item.Protocol, item.NATType, boolToInt(item.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateEgressNAT(db RuleStore, item *EgressNAT) error {
	_, err := db.Exec(
		`UPDATE egress_nats SET parent_interface=?, child_interface=?, out_interface=?, out_source_ip=?, protocol=?, nat_type=?, enabled=? WHERE id=?`,
		item.ParentInterface, item.ChildInterface, item.OutInterface, item.OutSourceIP, item.Protocol, item.NATType, boolToInt(item.Enabled), item.ID,
	)
	return err
}

func DeleteEgressNAT(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM egress_nats WHERE id = ?`, id)
	return err
}

func GetEgressNATs(db RuleStore) ([]EgressNAT, error) {
	return queryEgressNATs(db, `SELECT `+egressNATColumns+` FROM egress_nats`)
}

func GetEnabledEgressNATs(db RuleStore) ([]EgressNAT, error) {
	return queryEgressNATs(db, `SELECT `+egressNATColumns+` FROM egress_nats WHERE enabled = 1`)
}

func GetEgressNATsByIDs(db RuleStore, ids []int64) ([]EgressNAT, error) {
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
		chunkItems, err := queryEgressNATs(db, query, dbInt64Args(chunk)...)
		if err != nil {
			return nil, err
		}
		items = append(items, chunkItems...)
	}
	return items, nil
}

func queryEgressNATs(db RuleStore, query string, args ...interface{}) ([]EgressNAT, error) {
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

func GetEgressNAT(db RuleStore, id int64) (*EgressNAT, error) {
	item, err := scanEgressNAT(db.QueryRow(`SELECT `+egressNATColumns+` FROM egress_nats WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func GetEgressNATProtocolMapByIDs(db RuleStore, ids []int64) (map[int64]string, error) {
	return QueryProtocolMapByIDs(db, `SELECT id, protocol FROM egress_nats WHERE id IN (%s)`, ids, func(protocol string) string {
		return protocol
	})
}

func SetEgressNATEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE egress_nats SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
