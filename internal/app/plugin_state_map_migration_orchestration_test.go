package app

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestPluginEBPFStateMigrationCompletesOnlyAfterRuntimeCommit(t *testing.T) {
	migration := testPluginEBPFStateMigration("stateful")
	tests := []struct {
		name             string
		migrationFailure error
		postFailure      error
		commitFailure    error
		wantErr          bool
		wantCompleted    bool
	}{
		{name: "success", wantCompleted: true},
		{name: "migration_failure", migrationFailure: errors.New("injected migration failure"), wantErr: true},
		{name: "post_replay_failure", postFailure: errors.New("injected post replay failure"), wantErr: true},
		{name: "resource_commit_failure", commitFailure: errors.New("injected resource commit failure"), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := openTestDB(t)
			control := &pluginStateMigrationControlRuntimeTest{
				migrationFailure: test.migrationFailure,
				postFailure:      test.postFailure,
				commitFailure:    test.commitFailure,
			}
			dataplane := &pluginStateMigrationDataplaneRuntimeTest{pending: []PluginEBPFStateMigration{migration}}
			pm := &ProcessManager{
				db:                   db,
				cfg:                  pluginsEnabledTestConfig(&Config{}),
				pluginControlRuntime: control,
				pluginRuntime:        dataplane,
			}
			catalog := PluginCatalog{Plugins: []LoadedPlugin{{
				PluginManifest: PluginManifest{ID: "stateful", Name: "Stateful", Version: "2.0.0", Kind: "pipeline"},
				Status:         pluginStatusActive,
			}}}
			_, err := pm.reconcilePluginCatalogForRuntime(catalog)
			if (err != nil) != test.wantErr {
				t.Fatalf("reconcile error = %v, wantErr=%t", err, test.wantErr)
			}
			if got := len(dataplane.completed); (got == 1) != test.wantCompleted {
				t.Fatalf("completed migrations = %+v, wantCompleted=%t", dataplane.completed, test.wantCompleted)
			}
			if test.wantCompleted {
				if len(dataplane.pending) != 0 || control.commitCalls != 1 || control.rollbackCalls != 0 {
					t.Fatalf("success state pending=%+v commits=%d rollbacks=%d", dataplane.pending, control.commitCalls, control.rollbackCalls)
				}
			} else if len(dataplane.pending) != 1 || control.rollbackCalls != 1 {
				t.Fatalf("failure state pending=%+v commits=%d rollbacks=%d", dataplane.pending, control.commitCalls, control.rollbackCalls)
			}
		})
	}
}

type pluginStateMigrationControlRuntimeTest struct {
	migrationFailure error
	postFailure      error
	commitFailure    error
	transactionID    string
	commitCalls      int
	rollbackCalls    int
}

func (rt *pluginStateMigrationControlRuntimeTest) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		states[plugin.ID] = PluginRuntimeState{Mode: pluginRuntimeModeRegistered}
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func (rt *pluginStateMigrationControlRuntimeTest) Snapshot() pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{}
}

func (rt *pluginStateMigrationControlRuntimeTest) ApplyPluginResourceData(LoadedPlugin, PluginResource, []PluginResourceRecord) error {
	return nil
}

func (rt *pluginStateMigrationControlRuntimeTest) ApplyPluginAction(LoadedPlugin, PluginAction, json.RawMessage) error {
	return nil
}

func (rt *pluginStateMigrationControlRuntimeTest) QueryPluginAction(LoadedPlugin, PluginAction, json.RawMessage) (any, error) {
	return nil, nil
}

func (rt *pluginStateMigrationControlRuntimeTest) Close() error { return nil }

func (rt *pluginStateMigrationControlRuntimeTest) ApplyPluginEBPFStateMigrations(_ PluginCatalog, _ pluginRuntimeSnapshot, migrations []PluginEBPFStateMigration) ([]PluginEBPFStateMigration, map[string]error) {
	if rt.migrationFailure != nil {
		return nil, map[string]error{"stateful": rt.migrationFailure}
	}
	return append([]PluginEBPFStateMigration(nil), migrations...), nil
}

func (rt *pluginStateMigrationControlRuntimeTest) ReapplyPluginRuntimeResourcesAfterDataplane(PluginCatalog, pluginRuntimeSnapshot) map[string]error {
	if rt.postFailure != nil {
		return map[string]error{"stateful": rt.postFailure}
	}
	return nil
}

func (rt *pluginStateMigrationControlRuntimeTest) BeginPluginResourceMigrationTransaction() error {
	return rt.BeginPluginResourceMigrationTransactionWithID("migration-test")
}

func (rt *pluginStateMigrationControlRuntimeTest) BeginPluginResourceMigrationTransactionWithID(id string) error {
	rt.transactionID = id
	return nil
}

func (rt *pluginStateMigrationControlRuntimeTest) PluginResourceMigrationTransactionID() string {
	return rt.transactionID
}

func (rt *pluginStateMigrationControlRuntimeTest) CommitPluginResourceMigrationTransaction() error {
	rt.commitCalls++
	if rt.commitFailure != nil {
		return rt.commitFailure
	}
	rt.transactionID = ""
	return nil
}

func (rt *pluginStateMigrationControlRuntimeTest) RollbackPluginResourceMigrationTransaction() error {
	rt.rollbackCalls++
	rt.transactionID = ""
	return nil
}

type pluginStateMigrationDataplaneRuntimeTest struct {
	pending   []PluginEBPFStateMigration
	completed []PluginEBPFStateMigration
}

func (rt *pluginStateMigrationDataplaneRuntimeTest) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		states[plugin.ID] = PluginRuntimeState{Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true}
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func (rt *pluginStateMigrationDataplaneRuntimeTest) Snapshot() pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{}
}

func (rt *pluginStateMigrationDataplaneRuntimeTest) Close() error { return nil }

func (rt *pluginStateMigrationDataplaneRuntimeTest) PendingPluginEBPFStateMigrations() []PluginEBPFStateMigration {
	return append([]PluginEBPFStateMigration(nil), rt.pending...)
}

func (rt *pluginStateMigrationDataplaneRuntimeTest) CompletePluginEBPFStateMigrations(completed []PluginEBPFStateMigration) {
	rt.completed = append(rt.completed, completed...)
	done := make(map[string]struct{}, len(completed))
	for _, migration := range completed {
		done[migration.key()] = struct{}{}
	}
	pending := rt.pending[:0]
	for _, migration := range rt.pending {
		if _, ok := done[migration.key()]; !ok {
			pending = append(pending, migration)
		}
	}
	rt.pending = pending
}
