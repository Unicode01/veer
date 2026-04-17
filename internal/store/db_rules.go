package store

import "strings"

const ruleColumns = `id, in_interface, in_ip, in_port, out_interface, out_ip, out_source_ip, out_port, protocol, remark, tag, enabled, transparent, engine_preference`

func scanRule(sc interface{ Scan(...interface{}) error }) (Rule, error) {
	var r Rule
	var enabled, transparent int
	err := sc.Scan(&r.ID, &r.InInterface, &r.InIP, &r.InPort, &r.OutInterface, &r.OutIP, &r.OutSourceIP, &r.OutPort, &r.Protocol, &r.Remark, &r.Tag, &enabled, &transparent, &r.EnginePreference)
	r.Enabled = enabled != 0
	r.Transparent = transparent != 0
	return r, err
}

func AddRule(db RuleStore, r *Rule) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO rules (in_interface, in_ip, in_port, out_interface, out_ip, out_source_ip, out_port, protocol, remark, tag, enabled, transparent, engine_preference)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.EnginePreference,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateRule(db RuleStore, r *Rule) error {
	_, err := db.Exec(
		`UPDATE rules SET in_interface=?, in_ip=?, in_port=?, out_interface=?, out_ip=?, out_source_ip=?, out_port=?, protocol=?, remark=?, tag=?, enabled=?, transparent=?, engine_preference=? WHERE id=?`,
		r.InInterface, r.InIP, r.InPort, r.OutInterface, r.OutIP, r.OutSourceIP, r.OutPort, r.Protocol, r.Remark, r.Tag, boolToInt(r.Enabled), boolToInt(r.Transparent), r.EnginePreference, r.ID,
	)
	return err
}

func DeleteRule(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}

func GetRules(db RuleStore) ([]Rule, error) {
	return queryRules(db, `SELECT `+ruleColumns+` FROM rules`)
}

func GetEnabledRules(db RuleStore) ([]Rule, error) {
	return queryRules(db, `SELECT `+ruleColumns+` FROM rules WHERE enabled = 1`)
}

func GetRulesByIDs(db RuleStore, ids []int64) ([]Rule, error) {
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
	return queryRules(db, query, args...)
}

func GetRulesFiltered(db RuleStore, filters RuleFilter) ([]Rule, error) {
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

	return queryRules(db, query, args...)
}

func GetEnabledRulesByIDs(db RuleStore, ids []int64) ([]Rule, error) {
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
	return queryRules(db, query, args...)
}

func queryRules(db RuleStore, query string, args ...interface{}) ([]Rule, error) {
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

func GetRule(db RuleStore, id int64) (*Rule, error) {
	r, err := scanRule(db.QueryRow(`SELECT `+ruleColumns+` FROM rules WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func GetRuleMetaByIDs(db RuleStore, ids []int64) (map[int64]Rule, error) {
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

func GetRuleProtocolMapByIDs(db RuleStore, ids []int64) (map[int64]string, error) {
	return QueryProtocolMapByIDs(db, `SELECT id, protocol FROM rules WHERE id IN (%s)`, ids, func(protocol string) string {
		return protocol
	})
}

func SetRuleEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE rules SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
