package app

import "time"

type kernelRuntimePressureLevel string

const (
	kernelRuntimePressureLevelNone           kernelRuntimePressureLevel = ""
	kernelRuntimePressureLevelHold           kernelRuntimePressureLevel = "hold"
	kernelRuntimePressureLevelShed           kernelRuntimePressureLevel = "shed"
	kernelRuntimePressureLevelFull           kernelRuntimePressureLevel = "full"
	kernelRuntimePressureShedFallbackDivisor                            = 4
)

func (level kernelRuntimePressureLevel) active() bool {
	return level != kernelRuntimePressureLevelNone
}

func (level kernelRuntimePressureLevel) blocksKernelAvailability() bool {
	return level == kernelRuntimePressureLevelFull
}

func (level kernelRuntimePressureLevel) requiresRedistribute() bool {
	return level == kernelRuntimePressureLevelShed || level == kernelRuntimePressureLevelFull
}

type kernelRuntimePressureSnapshot struct {
	Engine          string
	Level           kernelRuntimePressureLevel
	Active          bool
	Reason          string
	AssignedEntries int
	SampledAt       time.Time
	FlowsEntries    int
	FlowsCapacity   int
	NATEntries      int
	NATCapacity     int
}

type kernelPressureAwareRuntime interface {
	pressureSnapshot() kernelRuntimePressureSnapshot
}

func (snapshot kernelRuntimePressureSnapshot) level() kernelRuntimePressureLevel {
	if snapshot.Level != kernelRuntimePressureLevelNone {
		return snapshot.Level
	}
	if snapshot.Active {
		return kernelRuntimePressureLevelHold
	}
	return kernelRuntimePressureLevelNone
}

func (snapshot kernelRuntimePressureSnapshot) active() bool {
	return snapshot.level().active()
}

func snapshotKernelRuntimePressure(rt kernelRuleRuntime) kernelRuntimePressureSnapshot {
	if aware, ok := rt.(kernelPressureAwareRuntime); ok && aware != nil {
		return aware.pressureSnapshot()
	}
	return kernelRuntimePressureSnapshot{}
}

func kernelRuntimeNeedsRedistribute(rt kernelRuleRuntime) (bool, string) {
	return kernelRuntimeNeedsRedistributeSnapshot(snapshotKernelRuntimePressure(rt))
}

func kernelRuntimeNeedsRedistributeSnapshot(snapshot kernelRuntimePressureSnapshot) (bool, string) {
	if !snapshot.level().requiresRedistribute() || snapshot.AssignedEntries <= 0 {
		return false, ""
	}
	return true, snapshot.Reason
}

func kernelRuntimePressureCleared(previous kernelRuntimePressureSnapshot, current kernelRuntimePressureSnapshot) bool {
	return previous.active() && !current.active()
}
