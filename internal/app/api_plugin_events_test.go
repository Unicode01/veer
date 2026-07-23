package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginEventDeadLetterAdminAPI(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	makeDead := func(id string) {
		t.Helper()
		item := store.PluginEventDelivery{
			DeliveryID: id, PluginID: "event_sink", SubscriptionID: "critical", Topic: "plugin.source.changed",
			PublishedAt: now.UTC().Format(time.RFC3339Nano), SourcePlugin: "source", TargetPlugin: "event_sink",
			SchemaVersion: 1, PayloadJSON: `{"value":1}`, MaxAttempts: 2, NextAttemptUnixMS: now.UnixMilli(),
		}
		if err := store.CreatePluginEventDeliveries(db, []store.PluginEventDelivery{item}, 10, 20); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkPluginEventDeliveryFailure(db, item.PluginID, item.DeliveryID, 2, now.UnixMilli(), true, "handler failed"); err != nil {
			t.Fatal(err)
		}
	}
	makeDead("30000000000000000000000000000001")
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "event-token", PluginAdminToken: "event-admin", PluginsDir: t.TempDir()})
	handler := buildAPIHandler(cfg, db, nil)
	request := func(method, path string, body string, admin bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer event-token")
		if admin {
			req.Header.Set(pluginAdminTokenHeader, "event-admin")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	listed := request(http.MethodGet, "/api/plugin-event-dead-letters?plugin_id=event_sink&limit=10", "", false)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"last_error":"handler failed"`) || !strings.Contains(listed.Body.String(), `"id":`) {
		t.Fatalf("dead-letter list = %d %s", listed.Code, listed.Body.String())
	}
	body := `{"plugin_id":"event_sink","delivery_id":"30000000000000000000000000000001"}`
	if denied := request(http.MethodPost, "/api/plugin-event-dead-letters/retry", body, false); denied.Code != http.StatusForbidden {
		t.Fatalf("retry without admin = %d %s", denied.Code, denied.Body.String())
	}
	retried := request(http.MethodPost, "/api/plugin-event-dead-letters/retry", body, true)
	if retried.Code != http.StatusOK || !strings.Contains(retried.Body.String(), `"status":"pending"`) {
		t.Fatalf("dead-letter retry = %d %s", retried.Code, retried.Body.String())
	}
	makeDead("30000000000000000000000000000002")
	body = `{"plugin_id":"event_sink","delivery_id":"30000000000000000000000000000002"}`
	discarded := request(http.MethodPost, "/api/plugin-event-dead-letters/discard", body, true)
	if discarded.Code != http.StatusOK || !strings.Contains(discarded.Body.String(), `"discarded":true`) {
		t.Fatalf("dead-letter discard = %d %s", discarded.Code, discarded.Body.String())
	}
	listed = request(http.MethodGet, "/api/plugin-event-dead-letters", "", false)
	if listed.Code != http.StatusOK || strings.TrimSpace(listed.Body.String()) != "[]" {
		t.Fatalf("dead-letter list after actions = %d %s", listed.Code, listed.Body.String())
	}
}
