package app

import "sync"

// pluginMutationGate keeps the plugin actions and resource writes made
// through the API apart from the plugin reconcile passes the daemon starts by
// itself (a retry after a failed pass, the dataplane self-heal).
//
// A reconcile pass journals every resource the plugins write during it so
// that a failed pass can restore them, and refuses other writes to those
// resources until it commits or rolls back. A pass can take seconds, since it
// includes the dataplane reconcile, and while a plugin keeps reporting an
// error the daemon retries every 250 ms to 1 min. An action that wrote the
// same resource meanwhile failed with "plugin resource migration is pending".
//
// API mutations run side by side. One waits while a background pass runs; a
// background pass does not start while one runs, so the maintenance loop is
// never held up behind an action and simply tries again later. Passes that
// an API mutation causes (its runtime update, or a plugin handler asking for
// one) and passes started by API requests that are not mutations bypass the
// gate.
type pluginMutationGate struct {
	mu        sync.Mutex
	cond      *sync.Cond
	mutations int
	pass      bool
}

func (g *pluginMutationGate) condLocked() *sync.Cond {
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	return g.cond
}

// enterMutation waits until no background pass runs and admits an API
// mutation; call the returned function when it is done.
func (g *pluginMutationGate) enterMutation() func() {
	g.mu.Lock()
	for g.pass {
		g.condLocked().Wait()
	}
	g.mutations++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.mutations--
			if g.mutations == 0 {
				g.condLocked().Broadcast()
			}
			g.mu.Unlock()
		})
	}
}

// tryEnterPass admits a background pass unless an API mutation or another
// background pass runs.
func (g *pluginMutationGate) tryEnterPass() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pass || g.mutations > 0 {
		return false
	}
	g.pass = true
	return true
}

func (g *pluginMutationGate) leavePass() {
	g.mu.Lock()
	g.pass = false
	g.condLocked().Broadcast()
	g.mu.Unlock()
}

// reconcilePluginsInBackground runs a reconcile pass the daemon starts by
// itself. It reports false, without running, while an API mutation runs; the
// caller tries again later. The gate is taken before pluginReconcileMu: a
// running API mutation may need that lock for its own runtime update.
func (pm *ProcessManager) reconcilePluginsInBackground() (bool, error) {
	if pm == nil {
		return false, nil
	}
	if !pm.pluginMutationGate.tryEnterPass() {
		return false, nil
	}
	defer pm.pluginMutationGate.leavePass()
	_, err := pm.reconcilePluginsForRuntimeWithError()
	return true, err
}

// beginPluginResourceMigrationAfterPass opens a package's resource migration
// transaction (install, batch install, probation rollback) once no reconcile
// pass runs. A pass owns a transaction of its own until it ends, and opening
// another meanwhile failed with "plugin resource migration transaction ... is
// already active". Passes that start later run inside the package's
// transaction, as part of the change it applies.
func (pm *ProcessManager) beginPluginResourceMigrationAfterPass(runtime pluginResourceMigrationTransactionRuntime, id string) error {
	pm.pluginReconcileMu.Lock()
	defer pm.pluginReconcileMu.Unlock()
	return runtime.BeginPluginResourceMigrationTransactionWithID(id)
}

// enterPluginAPIMutation admits a plugin action or resource write made
// through the API; see pluginMutationGate.
func (pm *ProcessManager) enterPluginAPIMutation() func() {
	if pm == nil {
		return func() {}
	}
	return pm.pluginMutationGate.enterMutation()
}
