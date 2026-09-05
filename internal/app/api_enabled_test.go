package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExplicitResourceEnabledIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	ruleID, err := dbAddRule(db, &Rule{InIP: "127.0.0.1", InPort: 23001, OutIP: "127.0.0.1", OutPort: 9, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	siteID, err := dbAddSite(db, &Site{Domain: "enabled.example.test", ListenIP: "127.0.0.1", BackendIP: "127.0.0.1", BackendHTTP: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, false, true, true} {
		for _, kind := range []string{"rules", "sites"} {
			id := ruleID
			if kind == "sites" {
				id = siteID
			}
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/%s/enabled?id=%d&enabled=%t", kind, id, enabled), nil)
			w := httptest.NewRecorder()
			if kind == "rules" {
				handleToggleRule(w, r, db, nil)
			} else {
				handleToggleSite(w, r, db, nil)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("%s enabled=%v: %d %s", kind, enabled, w.Code, w.Body.String())
			}
		}
		rule, _ := dbGetRule(db, ruleID)
		site, _ := dbGetSite(db, siteID)
		if rule.Enabled != enabled || site.Enabled != enabled {
			t.Fatalf("state reversed on repeat: rule=%v site=%v want=%v", rule.Enabled, site.Enabled, enabled)
		}
	}
}

func TestExplicitResourceEnabledRejectsAmbiguousInput(t *testing.T) {
	for _, query := range []string{"", "&enabled=", "&enabled=1", "&enabled=true&enabled=false"} {
		r := httptest.NewRequest(http.MethodPost, "/api/rules/enabled?id=1"+query, nil)
		w := httptest.NewRecorder()
		handleToggleRule(w, r, nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("query=%q status=%d", query, w.Code)
		}
	}
}
