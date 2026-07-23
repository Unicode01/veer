package app

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPluginControlCircuitIsolatesFailingHandlerAndRecovers(t *testing.T) {
	rt := newPluginControlRuntime(nil, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "circuit_plugin"}}
	event := pluginControlEvent{Kind: "action", Action: &PluginAction{ID: "fail"}}
	started := time.Unix(100, 0)

	for i := 0; i < pluginControlCircuitFailureThreshold; i++ {
		invocation, err := rt.beginPluginControlInvocation(plugin, event, started.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatalf("begin failure %d: %v", i, err)
		}
		rt.finishPluginControlInvocation(invocation, errors.New("handler failed"), invocation.started.Add(5*time.Millisecond))
	}

	if _, err := rt.beginPluginControlInvocation(plugin, event, started.Add(20*time.Millisecond)); err == nil || !strings.Contains(err.Error(), "is open until") {
		t.Fatalf("begin open circuit error = %v", err)
	}
	other := pluginControlEvent{Kind: "action", Action: &PluginAction{ID: "healthy"}}
	otherInvocation, err := rt.beginPluginControlInvocation(plugin, other, started.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("healthy handler was blocked by another circuit: %v", err)
	}
	rt.finishPluginControlInvocation(otherInvocation, nil, otherInvocation.started.Add(time.Millisecond))

	health := rt.pluginControlHealthSnapshot(plugin.ID)
	if health.Status != "quarantined" || health.OpenCircuits != 1 || health.Failures != pluginControlCircuitFailureThreshold || health.Rejected != 1 {
		t.Fatalf("health while open = %+v", health)
	}
	if health.AverageDurationMS <= 0 || health.MaxDurationMS < 5 {
		t.Fatalf("health duration metrics = %+v", health)
	}

	probeAt := started.Add(2 * pluginControlCircuitBaseBackoff)
	probe, err := rt.beginPluginControlInvocation(plugin, event, probeAt)
	if err != nil {
		t.Fatalf("begin recovery probe: %v", err)
	}
	if !probe.probe {
		t.Fatal("expired circuit invocation was not marked as a recovery probe")
	}
	rt.finishPluginControlInvocation(probe, nil, probeAt.Add(2*time.Millisecond))
	health = rt.pluginControlHealthSnapshot(plugin.ID)
	if health.Status != "healthy" || health.OpenCircuits != 0 {
		t.Fatalf("health after successful recovery probe = %+v", health)
	}
}

func TestPluginControlCircuitBackoffIsBounded(t *testing.T) {
	if got := pluginControlCircuitBackoff(1); got != pluginControlCircuitBaseBackoff {
		t.Fatalf("first backoff = %s", got)
	}
	if got := pluginControlCircuitBackoff(100); got != pluginControlCircuitMaxBackoff {
		t.Fatalf("bounded backoff = %s, want %s", got, pluginControlCircuitMaxBackoff)
	}
}
