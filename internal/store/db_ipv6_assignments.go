package store

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
	return item, err
}

func AddIPv6Assignment(db RuleStore, item *IPv6Assignment) (int64, error) {
	stored := *item
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

func UpdateIPv6Assignment(db RuleStore, item *IPv6Assignment) error {
	stored := *item
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

func DeleteIPv6Assignment(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM ipv6_assignments WHERE id = ?`, id)
	return err
}

func GetIPv6Assignments(db RuleStore) ([]IPv6Assignment, error) {
	return queryIPv6Assignments(db, `SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments`)
}

func GetEnabledIPv6Assignments(db RuleStore) ([]IPv6Assignment, error) {
	return queryIPv6Assignments(db, `SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments WHERE enabled = 1`)
}

func queryIPv6Assignments(db RuleStore, query string, args ...interface{}) ([]IPv6Assignment, error) {
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

func GetIPv6Assignment(db RuleStore, id int64) (*IPv6Assignment, error) {
	item, err := scanIPv6Assignment(db.QueryRow(`SELECT `+ipv6AssignmentColumns+` FROM ipv6_assignments WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &item, nil
}
