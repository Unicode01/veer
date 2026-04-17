package store

func AddSite(db RuleStore, s *Site) (int64, error) {
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

func UpdateSite(db RuleStore, s *Site) error {
	_, err := db.Exec(
		`UPDATE sites SET domain=?, listen_ip=?, listen_iface=?, backend_ip=?, backend_source_ip=?, backend_http=?, backend_https=?, tag=?, enabled=?, transparent=? WHERE id=?`,
		s.Domain, s.ListenIP, s.ListenIface, s.BackendIP, s.BackendSourceIP, s.BackendHTTP, s.BackendHTTPS, s.Tag, boolToInt(s.Enabled), boolToInt(s.Transparent), s.ID,
	)
	return err
}

func DeleteSite(db RuleStore, id int64) error {
	_, err := db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

func GetSites(db RuleStore) ([]Site, error) {
	return querySites(db, `SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent FROM sites`)
}

func GetEnabledSites(db RuleStore) ([]Site, error) {
	return querySites(db, `SELECT id, domain, listen_ip, listen_iface, backend_ip, backend_source_ip, backend_http, backend_https, tag, enabled, transparent FROM sites WHERE enabled = 1`)
}

func querySites(db RuleStore, query string, args ...interface{}) ([]Site, error) {
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

func CountEnabledSites(db RuleStore) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sites WHERE enabled = 1`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func GetSite(db RuleStore, id int64) (*Site, error) {
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

func SetSiteEnabled(db RuleStore, id int64, enabled bool) error {
	_, err := db.Exec(`UPDATE sites SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}
