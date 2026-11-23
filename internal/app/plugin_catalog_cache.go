package app

import (
	"reflect"
	"sync"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

// pluginCatalogStateTTL bounds how long cached enabled states are trusted
// without a write through the store, as pluginEnabledCacheTTL does for the
// control runtime.
const pluginCatalogStateTTL = time.Minute

// pluginCatalogCache keeps the catalog read from the applied plugin
// snapshot, so plugin API requests, dataplane reconciles and netlink
// recovery do not walk and hash every plugin file again (native libraries
// are megabytes each). Two layers: the directory scan, which changes only
// when the snapshot or the plugin settings do, and the scan with the stored
// enabled states applied, rechecked by store.PluginStateGeneration. Callers
// get deep copies; the overlays they add on top (runtime surfaces, hook
// bindings, database usage) are not cached.
type pluginCatalogCache struct {
	mu sync.Mutex

	scanKey pluginCatalogScanKey
	scanned *PluginCatalog

	stateGeneration uint64
	stateReadAt     time.Time
	stated          *PluginCatalog
}

// pluginCatalogScanKey holds everything loadPluginCatalog reads besides the
// directory contents, which do not change under a fixed source: a new
// applied snapshot is a new directory, and applying it invalidates the cache
// as well.
type pluginCatalogScanKey struct {
	dir             string
	externalEnabled bool
	limits          PluginResourceLimits
}

func newPluginCatalogScanKey(source pluginCatalogSource) pluginCatalogScanKey {
	return pluginCatalogScanKey{
		dir:             normalizePluginsDir(source.cfg.PluginsDir),
		externalEnabled: source.cfg.PluginsEnabled(),
		limits:          pluginResourceLimitsFromConfig(source.cfg),
	}
}

// invalidate drops the cached catalog: the next read scans again.
func (c *pluginCatalogCache) invalidate() {
	c.mu.Lock()
	c.scanned = nil
	c.stated = nil
	c.mu.Unlock()
}

// catalog returns the catalog for source with the enabled states in db
// applied, without database usage.
func (c *pluginCatalogCache) catalog(source pluginCatalogSource, db store.RuleStore) PluginCatalog {
	if !source.fixed {
		return applyPluginEnabledStatesFromDB(loadPluginCatalog(source.cfg), db)
	}
	key := newPluginCatalogScanKey(source)
	// Read before the states it guards: a write after this read makes the
	// states read below stale, and the next call reads them again.
	generation := store.PluginStateGeneration()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scanned == nil || c.scanKey != key {
		scanned := loadPluginCatalog(source.cfg)
		c.scanned = &scanned
		c.scanKey = key
		c.stated = nil
	}
	if c.stated == nil || c.stateGeneration != generation || now.Sub(c.stateReadAt) >= pluginCatalogStateTTL {
		stated := applyPluginEnabledStatesFromDB(clonePluginCatalog(*c.scanned), db)
		c.stated = &stated
		c.stateGeneration = generation
		c.stateReadAt = now
	}
	out := clonePluginCatalog(*c.stated)
	// Feature availability follows the host (an optional kernel module can
	// be loaded later); nothing in the scan reads it.
	out.Runtime = pluginRuntimeCapabilities(source.cfg)
	return out
}

// pluginCatalogWithState is loadPluginCatalogWithState for the running
// process: the applied snapshot's catalog with the stored enabled states,
// from the cache. It leaves out the database usage; the API views add it.
func (pm *ProcessManager) pluginCatalogWithState(fallback *Config) (PluginCatalog, *Config, string) {
	source := pm.appliedPluginCatalogSource(fallback)
	var db store.RuleStore
	if pm != nil && pm.db != nil {
		db = pm.db
	}
	if pm == nil {
		return applyPluginEnabledStatesFromDB(loadPluginCatalog(source.cfg), db), source.cfg, source.sourceDir
	}
	return pm.pluginCatalogCache.catalog(source, db), source.cfg, source.sourceDir
}

// invalidatePluginCatalogCache makes the next catalog read scan the applied
// snapshot again.
func (pm *ProcessManager) invalidatePluginCatalogCache() {
	if pm == nil {
		return
	}
	pm.pluginCatalogCache.invalidate()
}

// clonePluginCatalog returns a copy of catalog that shares no memory with
// it, so a caller may change the copy freely.
func clonePluginCatalog(catalog PluginCatalog) PluginCatalog {
	return deepCopyPluginValue(reflect.ValueOf(catalog)).Interface().(PluginCatalog)
}

// deepCopyPluginValue copies v and everything it references. Unexported
// struct fields are copied by value with their struct; the catalog types
// keep only plain values there (TestPluginCatalogTypesCloneDeeply).
func deepCopyPluginValue(v reflect.Value) reflect.Value {
	if !pluginCopyPlanFor(v.Type()).references {
		return v
	}
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	deepCopyPluginReferences(out)
	return out
}

// deepCopyPluginReferences replaces what v references with copies. v is
// settable and holds a shallow copy.
func deepCopyPluginReferences(v reflect.Value) {
	plan := pluginCopyPlanFor(v.Type())
	if !plan.references {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		elem := reflect.New(v.Type().Elem())
		elem.Elem().Set(v.Elem())
		deepCopyPluginReferences(elem.Elem())
		v.Set(elem)
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(out, v)
		if pluginCopyPlanFor(v.Type().Elem()).references {
			for i := 0; i < out.Len(); i++ {
				deepCopyPluginReferences(out.Index(i))
			}
		}
		v.Set(out)
	case reflect.Map:
		if v.IsNil() {
			return
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(deepCopyPluginValue(iter.Key()), deepCopyPluginValue(iter.Value()))
		}
		v.Set(out)
	case reflect.Interface:
		if !v.IsNil() {
			v.Set(deepCopyPluginValue(v.Elem()))
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			deepCopyPluginReferences(v.Index(i))
		}
	case reflect.Struct:
		for _, i := range plan.fields {
			deepCopyPluginReferences(v.Field(i))
		}
	}
}

// pluginCopyPlan is what deepCopyPluginValue needs to know about a type.
type pluginCopyPlan struct {
	// references is set when a value of the type can share memory with its
	// copy: it is or contains a pointer, slice, map, interface, channel or
	// function.
	references bool
	// fields are the struct fields to copy deeply: the exported ones that
	// hold references.
	fields []int
}

var pluginCopyPlans sync.Map // reflect.Type -> *pluginCopyPlan

func pluginCopyPlanFor(t reflect.Type) *pluginCopyPlan {
	if cached, ok := pluginCopyPlans.Load(t); ok {
		return cached.(*pluginCopyPlan)
	}
	plan := &pluginCopyPlan{}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		plan.references = true
	case reflect.Array:
		plan.references = pluginCopyPlanFor(t.Elem()).references
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !pluginCopyPlanFor(field.Type).references {
				continue
			}
			plan.references = true
			if field.IsExported() {
				plan.fields = append(plan.fields, i)
			}
		}
	}
	pluginCopyPlans.Store(t, plan)
	return plan
}
