package store

import (
	"path/filepath"
	"testing"
)

func TestGetPluginOwnedResourcesByPluginIDs(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "owned-resources.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	items := []PluginOwnedResource{
		{PluginID: "alpha", ResourceType: "link", ResourceKey: "alpha0", MetadataJSON: `{}`},
		{PluginID: "beta", ResourceType: "route", ResourceKey: "beta0", MetadataJSON: `{}`},
		{PluginID: "alpha", ResourceType: "address", ResourceKey: "alpha1", MetadataJSON: `{}`},
		{PluginID: "ignored", ResourceType: "link", ResourceKey: "ignored0", MetadataJSON: `{}`},
	}
	for _, item := range items {
		if err := AddPluginOwnedResource(db, item); err != nil {
			t.Fatal(err)
		}
	}

	resources, err := GetPluginOwnedResourcesByPluginIDs(db, []string{" beta ", "alpha", "missing", "alpha", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 3 {
		t.Fatalf("plugin count = %d, want 3", len(resources))
	}
	if got := resources["alpha"]; len(got) != 2 || got[0].ResourceKey != "alpha0" || got[1].ResourceKey != "alpha1" {
		t.Fatalf("alpha resources = %+v", got)
	}
	if got := resources["beta"]; len(got) != 1 || got[0].ResourceKey != "beta0" {
		t.Fatalf("beta resources = %+v", got)
	}
	if got := resources["missing"]; got == nil || len(got) != 0 {
		t.Fatalf("missing resources = %#v, want non-nil empty slice", got)
	}
}
