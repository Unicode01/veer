//go:build !linux

package app

func (pm *ProcessManager) startKernelNetlinkMonitor() {}

func (pm *ProcessManager) stopKernelNetlinkMonitor() {}

func normalizeKernelNetlinkRecoveryTrigger(trigger kernelNetlinkRecoveryTrigger) kernelNetlinkRecoveryTrigger {
	return trigger
}
