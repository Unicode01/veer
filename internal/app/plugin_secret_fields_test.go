package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginSecretsNestedMigrationAndRotation(t *testing.T) {
	db := openTestDB(t)
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	resource := PluginResource{ID: "config", SecretFields: []string{"password"}}
	plaintxt := `{"password":"old-top-secret","wan":{"password":"legacy-secret","pppoe":{"password":"nested-secret","username":"alice"}},"accounts":[{"Password":"array-secret"}]}`
	// A record may already have an encrypted top-level field when nested
	// protection is introduced. Migration must still encrypt every descendant.
	var mixed map[string]json.RawMessage
	_ = json.Unmarshal([]byte(plaintxt), &mixed)
	mixed["password"], err = secrets.encryptJSON("router_wizard", resource.ID, "default", "password", mixed["password"])
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(mixed)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{PluginID: "router_wizard", ResourceID: resource.ID, RecordKey: "default", DataJSON: string(data), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{PluginManifest: PluginManifest{ID: "router_wizard"}, Resources: []PluginResource{resource}}}}
	if err := secrets.migratePluginSecrets(catalog); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		record, err := store.GetPluginRecord(db, "router_wizard", resource.ID, "default")
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"old-top-secret", "legacy-secret", "nested-secret", "array-secret"} {
			if strings.Contains(record.DataJSON, value) || strings.Contains(string(redactPluginResourceData(plaintxt, resource)), value) {
				t.Fatal("secret remained in stored or API-visible data")
			}
		}
		plain, encrypted, err := secrets.decryptRecordData("router_wizard", resource, "default", record.DataJSON)
		if err != nil || !encrypted {
			t.Fatalf("decrypt migrated record: encrypted=%v, err=%v", encrypted, err)
		}
		assertSecretJSONEqual(t, plain, plaintxt)
	}
	check()
	if _, err := secrets.rotate(catalog); err != nil {
		t.Fatal(err)
	}
	check()
	// Removed/unavailable plugins must retain readable nested envelopes too.
	if _, err := secrets.rotate(PluginCatalog{}); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestPluginSecretsNestedUpdatePreservesOnlyOmittedSecrets(t *testing.T) {
	resource := PluginResource{SecretFields: []string{"password"}}
	existing := `{"wan":{"pppoe":{"password":"saved","username":"alice"}},"accounts":[{"password":"array-secret","name":"old"}]}`
	for _, tc := range []struct{ next, want string }{
		{`{"wan":{"pppoe":{"password":"__redacted__","username":"bob"}}}`, `{"wan":{"pppoe":{"password":"saved","username":"bob"}}}`},
		{`{"wan":{"mode":"existing"}}`, `{"wan":{"mode":"existing","pppoe":{"password":"saved"}}}`},
		{`{"wan":{"pppoe":{"password":""}}}`, `{"wan":{"pppoe":{"password":""}}}`},
		{`{"wan":null,"accounts":[{"password":"__redacted__","name":"new"}]}`, `{"wan":null,"accounts":[{"password":"array-secret","name":"new"}]}`},
	} {
		merged, _, err := mergePluginSecretFieldsForUpdate([]byte(tc.next), []byte(existing), resource)
		if err != nil {
			t.Fatal(err)
		}
		assertSecretJSONEqual(t, string(merged), tc.want)
	}
}

func assertSecretJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var left, right any
	if json.Unmarshal([]byte(got), &left) != nil || json.Unmarshal([]byte(want), &right) != nil || !reflect.DeepEqual(left, right) {
		t.Fatal("JSON round trip did not preserve the expected structure and values")
	}
}
