package store

import "strings"

const rangeColumns = `id, in_interface, in_ip, start_port, end_port, out_interface, out_ip, out_source_ip, out_start_port, protocol, remark, tag, enabled, transparent`

func scanPortRange(sc interface{ Scan(...interface{}) error }) (PortRange, error) {
	var r PortRange
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.StartPort, &r.EndPort, &r.OutInterface, &r.OutIP, &r.OutSourceIP, &r.OutStartPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	return r, err
}

func AddRange(db RuleStore, r *PortRange) (int64, error) {
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

func UpdateRange(db RuleStore, r *PortRange) error {
	_, err := db.Exec(
		`UPDATE ranges SET in_interface=?, in_ip=?, start_port=?, end_port=?, out_interface=?, out_ip=?, out_source_ip=?, out_start_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		r.InInterface, r.InIP, r.StartPort, r.EndPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutStartPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.ID,
	)
	return err
}

func DeleteRange(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM ranges WHERE id = ?`, id)
	return err
}

func GetRanges(db RuleStore) ([]PortRange, error) {
	return queryRanges(db, `SELECT `+rangeColumns+` FROM ranges`)
}

func GetEnabledRanges(db RuleStore) ([]PortRange, error) {
	return queryRanges(db, `SELECT `+rangeColumns+` FROM ranges WHERE enabled = 1`)
}

func GetEnabledRangesByIDs(db RuleStore, ids []int64) ([]PortRange, error) {
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
	return queryRanges(db, query, args...)
}

func queryRanges(db RuleStore, query string, args ...interface{}) ([]PortRange, error) {
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

func GetRange(db RuleStore, id int64) (*PortRange, error) {
	r, err := scanPortRange(db.QueryRow(`SELECT `+rangeColumns+` FROM ranges WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func GetRangeMetaByIDs(db RuleStore, ids []int64) (map[int64]PortRange, error) {
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

func GetRangeProtocolMapByIDs(db RuleStore, ids []int64) (map[int64]string, error) {
	return QueryProtocolMapByIDs(db, `SELECT id, protocol FROM ranges WHERE id IN (%s)`, ids, func(protocol string) string {
		return protocol
	})
}

func SetRangeEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE ranges SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
