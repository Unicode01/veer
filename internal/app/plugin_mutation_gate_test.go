package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

// A reconcile pass journals what plugins write during it until it ends. An
// action that writes the same resource while a pass the daemon started by
// itself runs (a retry after a failed pass) waits for the pass instead of
// failing with "plugin resource migration is pending".
func TestPluginActionWaitsForBackgroundReconcilePass(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir, WebToken: "gate-token"})
	writeTestPlugin(t, dir, "gate_a_writer", `{
  "api_version":"v1","id":"gate_a_writer","name":"Gate Writer","version":"1.0.0","kind":"control",
  "actions":[{"id":"set","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["plugin.register","resource"]}
}`)
	writePluginControlScript(t, dir, "gate_a_writer", `
plugin.resource({id:"items",methods:["list"],control_methods:["list","get","create","update","delete"],runtime_update:"manual"});
exports.onReconcile = function () { resources.set("items", "reconcile", {by:"reconcile"}, true, false); };
exports.onAction = function () { resources.set("items", "action", {by:"action"}, true, false); };
`)
	// Reconciled after the writer, it keeps the pass open with the writer's
	// resource journaled.
	writeTestPlugin(t, dir, "gate_b_slow", `{
  "api_version":"v1","id":"gate_b_slow","name":"Gate Slow","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "gate_b_slow", `
exports.onReconcile = function () { var end = Date.now() + 700; while (Date.now() < end) {} };
`)
	control := newPluginControlRuntime(db, cfg, nil).(*pluginControlManager)
	defer control.Close()
	pm := &ProcessManager{db: db, cfg: cfg, pluginControlRuntime: control}
	if _, err := pm.reconcilePluginsForRuntimeWithError(); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	passDone := make(chan error, 1)
	go func() {
		ran, err := pm.reconcilePluginsInBackground()
		if err == nil && !ran {
			err = errors.New("the background pass did not run")
		}
		passDone <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, err := store.PluginResourceSchemaStateOrNil(db, "gate_a_writer", "items")
		if err != nil {
			t.Fatal(err)
		}
		if state != nil && state.Status == "pending" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background pass never journaled the resource: %+v", state)
		}
		time.Sleep(5 * time.Millisecond)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/gate_a_writer/actions/set", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer gate-token")
	rec := httptest.NewRecorder()
	buildAPIHandler(cfg, db, pm).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("action during a background pass: status %d body %s", rec.Code, rec.Body.String())
	}
	if err := <-passDone; err != nil {
		t.Fatalf("background pass: %v", err)
	}
	if record, err := store.GetPluginRecord(db, "gate_a_writer", "items", "action"); err != nil || record.DataJSON != `{"by":"action"}` {
		t.Fatalf("action record = %+v, err=%v", record, err)
	}
	if state, err := store.PluginResourceSchemaStateOrNil(db, "gate_a_writer", "items"); err != nil || state == nil || state.Status != "active" {
		t.Fatalf("schema state after both = %+v, err=%v", state, err)
	}
}

// A reconcile pass owns a resource migration transaction while it runs. A
// plugin package install, batch install or probation rollback that opens its
// own meanwhile waits for the pass instead of failing with "plugin resource
// migration transaction ... is already active".
func TestPluginPackageMigrationWaitsForReconcilePass(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	writeTestPlugin(t, dir, "gate_slow", `{
  "api_version":"v1","id":"gate_slow","name":"Gate Slow","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "gate_slow", `
exports.onReconcile = function () { var end = Date.now() + 500; while (Date.now() < end) {} };
`)
	control := newPluginControlRuntime(db, cfg, nil).(*pluginControlManager)
	defer control.Close()
	pm := &ProcessManager{db: db, cfg: cfg, pluginControlRuntime: control}
	manager := &pluginPackageManager{cfg: cfg, db: db, pm: pm}

	for _, begin := range []struct {
		name string
		run  func(id string) error
	}{
		{"package", func(id string) error {
			return manager.beginPackageResourceMigration(pluginPackageTransaction{ResourceMigrationID: id})
		}},
		{"batch", func(id string) error {
			return manager.beginPluginPackageBatchResourceMigration(pluginPackageBatchTransaction{ResourceMigrationID: id})
		}},
	} {
		t.Run(begin.name, func(t *testing.T) {
			passDone := make(chan error, 1)
			go func() {
				_, err := pm.reconcilePluginsForRuntimeWithError()
				passDone <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for control.PluginResourceMigrationTransactionID() == "" {
				if time.Now().After(deadline) {
					t.Fatal("the pass never opened its transaction")
				}
				time.Sleep(time.Millisecond)
			}
			id, err := newPluginPackageID()
			if err != nil {
				t.Fatal(err)
			}
			if err := begin.run(id); err != nil {
				t.Fatalf("begin during a pass: %v", err)
			}
			if err := <-passDone; err != nil {
				t.Fatalf("pass: %v", err)
			}
			if got := control.PluginResourceMigrationTransactionID(); got != id {
				t.Fatalf("open transaction %q, want %q", got, id)
			}
			if err := control.RollbackPluginResourceMigrationTransaction(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A background pass does not wait for an API mutation that is running: it
// reports that it did not run, so the maintenance loop that started it is
// not held up and tries again shortly.
func TestBackgroundReconcilePassDefersToAPIMutation(t *testing.T) {
	pm := &ProcessManager{}
	release := pm.pluginMutationGate.enterMutation()
	if ran, err := pm.reconcilePluginsInBackground(); ran || err != nil {
		t.Fatalf("pass during an API mutation ran=%t err=%v", ran, err)
	}
	release()
	if ran, err := pm.reconcilePluginsInBackground(); !ran || err != nil {
		t.Fatalf("pass after the mutation ran=%t err=%v", ran, err)
	}

	// And an API mutation waits for a pass that is running.
	if !pm.pluginMutationGate.tryEnterPass() {
		t.Fatal("idle gate refused a pass")
	}
	entered := make(chan struct{})
	go func() {
		defer close(entered)
		pm.pluginMutationGate.enterMutation()()
	}()
	select {
	case <-entered:
		t.Fatal("an API mutation entered during a pass")
	case <-time.After(50 * time.Millisecond):
	}
	pm.pluginMutationGate.leavePass()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the API mutation never entered after the pass")
	}
}

// Changes that run passes of their own (enable/disable, runtime updates, a
// rollback) used to run side by side with other API writes, which then failed
// on the resources the pass journaled. Changes now take turns.
func TestPluginChangesTakeTurns(t *testing.T) {
	pm := &ProcessManager{}
	first := pm.enterPluginChange()
	entered := make(chan struct{})
	go func() {
		defer close(entered)
		pm.enterPluginChange()()
	}()
	select {
	case <-entered:
		t.Fatal("a second change entered while the first ran")
	case <-time.After(50 * time.Millisecond):
	}
	first()
	first() // leaving twice is harmless
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the second change never entered after the first")
	}
	if !pm.pluginMutationGate.tryEnterPass() {
		t.Fatal("the gate refused a background pass after every change left")
	}
	pm.pluginMutationGate.leavePass()
}
