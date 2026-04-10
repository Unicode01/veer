package app

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestInitDBCreatesAllDefinedIndexes(t *testing.T) {
	db := openTestDB(t)

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'index'`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	defer rows.Close()

	got := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		got[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index names: %v", err)
	}

	for _, index := range schemaIndexes {
		if _, ok := got[index.Name]; !ok {
			t.Fatalf("missing index %q", index.Name)
		}
	}
}

func TestDBGetRulesFilteredAppliesExactSQLFilters(t *testing.T) {
	db := openTestDB(t)

	match := Rule{
		InInterface:  "wan0",
		InIP:         "198.51.100.10",
		InPort:       443,
		OutInterface: "lan0",
		OutIP:        "203.0.113.10",
		OutSourceIP:  "203.0.113.1",
		OutPort:      8443,
		Protocol:     "TCP",
		Remark:       "primary",
		Tag:          "prod",
		Enabled:      true,
		Transparent:  false,
	}
	matchID, err := dbAddRule(db, &match)
	if err != nil {
		t.Fatalf("add matching rule: %v", err)
	}
	others := []Rule{
		{
			InInterface:  "wan0",
			InIP:         "198.51.100.10",
			InPort:       443,
			OutInterface: "lan0",
			OutIP:        "203.0.113.10",
			OutSourceIP:  "203.0.113.1",
			OutPort:      8443,
			Protocol:     "udp",
			Tag:          "prod",
			Enabled:      true,
		},
		{
			InInterface:  "wan0",
			InIP:         "198.51.100.10",
			InPort:       443,
			OutInterface: "lan0",
			OutIP:        "203.0.113.10",
			OutSourceIP:  "203.0.113.1",
			OutPort:      8443,
			Protocol:     "tcp",
			Tag:          "prod",
			Enabled:      false,
		},
		{
			InInterface:  "wan1",
			InIP:         "198.51.100.11",
			InPort:       80,
			OutInterface: "lan1",
			OutIP:        "203.0.113.11",
			OutSourceIP:  "203.0.113.2",
			OutPort:      8080,
			Protocol:     "tcp",
			Tag:          "stage",
			Enabled:      true,
			Transparent:  true,
		},
	}
	for _, rule := range others {
		if _, err := dbAddRule(db, &rule); err != nil {
			t.Fatalf("add non-matching rule: %v", err)
		}
	}

	enabled := true
	transparent := false
	rules, err := dbGetRulesFiltered(db, ruleFilter{
		IDs:          map[int64]struct{}{matchID: {}},
		Tags:         map[string]struct{}{"prod": {}},
		Protocols:    map[string]struct{}{"tcp": {}},
		Enabled:      &enabled,
		Transparent:  &transparent,
		InInterface:  "wan0",
		OutInterface: "lan0",
		InIP:         "198.51.100.10",
		OutIP:        "203.0.113.10",
		OutSourceIP:  "203.0.113.1",
		InPort:       443,
		OutPort:      8443,
	})
	if err != nil {
		t.Fatalf("dbGetRulesFiltered() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("dbGetRulesFiltered() len = %d, want 1", len(rules))
	}
	if rules[0].ID != matchID {
		t.Fatalf("dbGetRulesFiltered() id = %d, want %d", rules[0].ID, matchID)
	}
}

func TestHandleListRulesCombinesDBAndRuntimeFilters(t *testing.T) {
	db := openTestDB(t)

	running := Rule{
		InInterface: "wan0",
		InIP:        "198.51.100.20",
		InPort:      443,
		OutIP:       "203.0.113.20",
		OutPort:     8443,
		Protocol:    "tcp",
		Remark:      "primary route",
		Tag:         "edge",
		Enabled:     true,
	}
	runningID, err := dbAddRule(db, &running)
	if err != nil {
		t.Fatalf("add running rule: %v", err)
	}
	stopped := Rule{
		InInterface: "wan0",
		InIP:        "198.51.100.21",
		InPort:      443,
		OutIP:       "203.0.113.21",
		OutPort:     8443,
		Protocol:    "tcp",
		Remark:      "primary standby",
		Tag:         "edge",
		Enabled:     true,
	}
	if _, err := dbAddRule(db, &stopped); err != nil {
		t.Fatalf("add stopped rule: %v", err)
	}
	queryMiss := Rule{
		InInterface: "wan0",
		InIP:        "198.51.100.22",
		InPort:      443,
		OutIP:       "203.0.113.22",
		OutPort:     8443,
		Protocol:    "tcp",
		Remark:      "secondary route",
		Tag:         "edge",
		Enabled:     true,
	}
	queryMissID, err := dbAddRule(db, &queryMiss)
	if err != nil {
		t.Fatalf("add query-miss rule: %v", err)
	}

	pm := &ProcessManager{
		rulePlans:         map[int64]ruleDataplanePlan{},
		kernelRuleEngines: map[int64]string{},
		kernelRules: map[int64]bool{
			runningID:   true,
			queryMissID: true,
		},
	}

	req := httptest.NewRequest("GET", "/api/rules?enabled=true&tag=edge&protocol=tcp&status=running&q=primary", nil)
	w := httptest.NewRecorder()

	handleListRules(w, req, db, pm)
	if w.Code != 200 {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var items []RuleStatus
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].ID != runningID {
		t.Fatalf("items[0].ID = %d, want %d", items[0].ID, runningID)
	}
	if items[0].Status != "running" {
		t.Fatalf("items[0].Status = %q, want running", items[0].Status)
	}
}
