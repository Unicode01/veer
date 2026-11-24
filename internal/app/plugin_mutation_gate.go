package app

import "sync"

// pluginMutationGate keeps plugin changes apart from one another and from the
// plugin reconcile passes the daemon starts by itself (a retry after a failed
// pass, the dataplane self-heal). The changes are the actions, resource
// writes, enable/disable and catalog reloads made through the API, and the
// automatic rollback of a package on probation.
//
// A reconcile pass journals every resource the plugins write during it so
// that a failed pass can restore them, and refuses other writes to those
// resources until it commits or rolls back. A pass can take seconds, since it
// includes the dataplane reconcile, and while a plugin keeps reporting an
// error the daemon retries every 250 ms to 1 min. A write to the same
// resource meanwhile failed with "plugin resource migration is pending".
//
// Many changes run a pass of their own (enable/disable, a runtime update, a
// plugin handler asking for one, a rollback), so they take turns: one waits
// while another change or a background pass runs. A background pass does not
// start while a change runs, so the maintenance loop is never held up behind
// one and simply tries again later. The passes a change runs belong to it and
// do not take the gate again.
type pluginMutationGate struct {
	mu       sync.Mutex
	cond     *sync.Cond
	changing bool
	pass     bool
}

func (g *pluginMutationGate) condLocked() *sync.Cond {
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	return g.cond
}

// enterMutation waits until no other change and no background pass runs and
// admits a change; call the returned function when it is done.
func (g *pluginMutationGate) enterMutation() func() {
	g.mu.Lock()
	for g.pass || g.changing {
		g.condLocked().Wait()
	}
	g.changing = true
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.changing = false
			g.condLocked().Broadcast()
			g.mu.Unlock()
		})
	}
}

// tryEnterPass admits a background pass unless a change or another
// background pass runs.
func (g *pluginMutationGate) tryEnterPass() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pass || g.changing {
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
// itself. It reports false, without running, while a change runs; the caller
// tries again later. The gate is taken before pluginReconcileMu: a running
// change may need that lock for its own runtime update.
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

// enterPluginChange admits a plugin change; see pluginMutationGate. Nothing a
// change runs may enter again: the gate is not reentrant.
func (pm *ProcessManager) enterPluginChange() func() {
	if pm == nil {
		return func() {}
	}
	return pm.pluginMutationGate.enterMutation()
}
