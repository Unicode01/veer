package app

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	kernelMaintenanceFullScanEvery    = 6
	kernelMaintenanceFullScanMinEvery = 3
	kernelMaintenanceFullScanMaxEvery = 12
)

type kernelAttachmentHealthSnapshot struct {
	Engine        string
	Loaded        bool
	ActiveEntries int
	Healthy       bool
}

type kernelAttachmentHealthRuntime interface {
	attachmentHealthSnapshot() []kernelAttachmentHealthSnapshot
}

type kernelAttachmentHealResult struct {
	Engine     string
	Reattached int
	Detached   int
}

type kernelAttachmentHealRuntime interface {
	healAttachments() ([]kernelAttachmentHealResult, error)
}

type kernelAdaptiveMaintenanceState struct {
	cyclesSinceFull int
	forceFull       bool
	fullScanEvery   int
}

func snapshotKernelAttachmentHealth(rt kernelRuleRuntime) []kernelAttachmentHealthSnapshot {
	if aware, ok := rt.(kernelAttachmentHealthRuntime); ok && aware != nil {
		return aware.attachmentHealthSnapshot()
	}
	return nil
}

func healKernelAttachments(rt kernelRuleRuntime) ([]kernelAttachmentHealResult, error) {
	if healer, ok := rt.(kernelAttachmentHealRuntime); ok && healer != nil {
		return healer.healAttachments()
	}
	return nil, nil
}

func summarizeUnhealthyKernelAttachments(items []kernelAttachmentHealthSnapshot) string {
	if len(items) == 0 {
		return ""
	}

	labels := make([]string, 0, len(items))
	for _, item := range items {
		if item.ActiveEntries <= 0 || item.Healthy {
			continue
		}
		engine := strings.TrimSpace(item.Engine)
		if engine == "" {
			engine = "kernel"
		}
		labels = append(labels, fmt.Sprintf("%s(active_entries=%d)", engine, item.ActiveEntries))
	}
	if len(labels) == 0 {
		return ""
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func summarizeKernelAttachmentHealResults(items []kernelAttachmentHealResult) string {
	if len(items) == 0 {
		return ""
	}

	labels := make([]string, 0, len(items))
	for _, item := range items {
		if item.Reattached <= 0 && item.Detached <= 0 {
			continue
		}
		engine := strings.TrimSpace(item.Engine)
		if engine == "" {
			engine = "kernel"
		}
		labels = append(labels, fmt.Sprintf("%s(reattach=%d detach=%d)", engine, item.Reattached, item.Detached))
	}
	if len(labels) == 0 {
		return ""
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func kernelAttachmentHealOutcomeSummary(rawSummary string, remainingIssue string) string {
	rawSummary = strings.TrimSpace(rawSummary)
	if rawSummary != "" {
		return rawSummary
	}
	if strings.TrimSpace(remainingIssue) == "" {
		return "issue cleared without targeted attachment changes"
	}
	return "no targeted attachment changes applied"
}

func (state *kernelAdaptiveMaintenanceState) requestFull() {
	if state == nil {
		return
	}
	state.forceFull = true
}

func (state *kernelAdaptiveMaintenanceState) reset() {
	if state == nil {
		return
	}
	*state = kernelAdaptiveMaintenanceState{}
}

func (state *kernelAdaptiveMaintenanceState) fullScanCadence() int {
	if state == nil || state.fullScanEvery <= 0 {
		return kernelMaintenanceFullScanEvery
	}
	if state.fullScanEvery < kernelMaintenanceFullScanMinEvery {
		return kernelMaintenanceFullScanMinEvery
	}
	if state.fullScanEvery > kernelMaintenanceFullScanMaxEvery {
		return kernelMaintenanceFullScanMaxEvery
	}
	return state.fullScanEvery
}

func (state *kernelAdaptiveMaintenanceState) shouldRunFull(pressureActive bool) bool {
	if state == nil {
		return true
	}
	if pressureActive || state.forceFull {
		state.cyclesSinceFull = 0
		state.forceFull = false
		return true
	}
	state.cyclesSinceFull++
	if state.cyclesSinceFull >= state.fullScanCadence() {
		state.cyclesSinceFull = 0
		return true
	}
	return false
}

func (state *kernelAdaptiveMaintenanceState) observeFull(pressureActive bool, success bool, driftDetected bool) {
	if state == nil {
		return
	}
	switch {
	case !success || driftDetected:
		state.fullScanEvery = kernelMaintenanceFullScanMinEvery
	case pressureActive:
		if state.fullScanEvery <= 0 {
			state.fullScanEvery = kernelMaintenanceFullScanEvery
		}
	case state.fullScanEvery <= 0:
		state.fullScanEvery = kernelMaintenanceFullScanEvery
	case state.fullScanEvery < kernelMaintenanceFullScanMaxEvery:
		state.fullScanEvery++
	}
}

func nextKernelAttachmentHealState(previousIssue string, lastHealAt time.Time, now time.Time, currentIssue string) (string, string, bool, time.Time) {
	nextIssue := previousIssue
	nextHealAt := lastHealAt
	recovered := ""
	heal := false

	switch {
	case strings.TrimSpace(currentIssue) == "":
		if strings.TrimSpace(previousIssue) != "" {
			recovered = previousIssue
		}
		nextIssue = ""
	case lastHealAt.IsZero() || now.Sub(lastHealAt) >= kernelAttachmentHealBackoff:
		nextIssue = currentIssue
		nextHealAt = now
		heal = true
	default:
		nextIssue = currentIssue
	}
	return nextIssue, recovered, heal, nextHealAt
}
