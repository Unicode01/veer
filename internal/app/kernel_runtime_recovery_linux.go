//go:build linux

package app

import (
	"fmt"
	"strings"
)

func (rt *linuxKernelRuleRuntime) attachmentHealthSnapshot() []kernelAttachmentHealthSnapshot {
	rt.mu.Lock()
	loaded := rt.coll != nil
	preparedRules := append([]preparedKernelRule(nil), rt.preparedRules...)
	attachments := append([]kernelAttachment(nil), rt.attachments...)
	mode := rt.attachmentMode
	programs := kernelAttachmentProgramsForPreparedRules(rt.coll, preparedRules, mode)
	rt.mu.Unlock()

	healthy := true
	if len(preparedRules) > 0 {
		forwardIfRules, replyIfRules := preparedKernelInterfaceRuleSets(preparedRules)
		healthy = kernelAttachmentsHealthy(
			forwardIfRules,
			replyIfRules,
			attachments,
			programs.forwardProg,
			programs.replyProg,
			programs.forwardProgV6,
			programs.replyProgV6,
		)
	}
	return []kernelAttachmentHealthSnapshot{{
		Engine:        kernelEngineTC,
		Loaded:        loaded,
		ActiveEntries: len(preparedRules),
		Healthy:       healthy,
	}}
}

func (rt *xdpKernelRuleRuntime) attachmentHealthSnapshot() []kernelAttachmentHealthSnapshot {
	rt.mu.Lock()
	loaded := rt.coll != nil
	preparedRules := append([]preparedXDPKernelRule(nil), rt.preparedRules...)
	attachments := append([]xdpAttachment(nil), rt.attachments...)
	programID := rt.programID
	rt.mu.Unlock()

	healthy := true
	if len(preparedRules) > 0 {
		requiredIfIndices := collectXDPInterfaces(preparedRules)
		healthy = xdpAttachmentsHealthy(requiredIfIndices, attachments, programID)
	}
	return []kernelAttachmentHealthSnapshot{{
		Engine:        kernelEngineXDP,
		Loaded:        loaded,
		ActiveEntries: len(preparedRules),
		Healthy:       healthy,
	}}
}

func (rt *orderedKernelRuleRuntime) attachmentHealthSnapshot() []kernelAttachmentHealthSnapshot {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	out := make([]kernelAttachmentHealthSnapshot, 0, len(entries))
	for _, entry := range entries {
		aware, ok := entry.rt.(kernelAttachmentHealthRuntime)
		if !ok || aware == nil {
			continue
		}
		items := aware.attachmentHealthSnapshot()
		for _, item := range items {
			if strings.TrimSpace(item.Engine) == "" {
				item.Engine = entry.name
			}
			out = append(out, item)
		}
	}
	return out
}

func (rt *linuxKernelRuleRuntime) healAttachments() ([]kernelAttachmentHealResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.coll == nil || rt.coll.Maps == nil || len(rt.preparedRules) == 0 {
		return nil, nil
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return nil, err
	}
	programs := kernelAttachmentProgramsFromPieces(pieces, kernelPreparedRulesIncludeIPv6(rt.preparedRules), rt.attachmentMode)
	forwardIfRules, replyIfRules := preparedKernelInterfaceRuleSets(rt.preparedRules)
	if kernelAttachmentsHealthy(
		forwardIfRules,
		replyIfRules,
		rt.attachments,
		programs.forwardProg,
		programs.replyProg,
		programs.forwardProgV6,
		programs.replyProgV6,
	) {
		return nil, nil
	}
	plans := desiredKernelAttachmentPlansDualStack(
		forwardIfRules,
		replyIfRules,
		programs.forwardProg,
		programs.replyProg,
		programs.forwardProgV6,
		programs.replyProgV6,
	)
	if len(plans) == 0 {
		return nil, nil
	}

	oldAttachments := append([]kernelAttachment(nil), rt.attachments...)
	currentAttachments := make(map[kernelAttachmentKey]kernelAttachment, len(oldAttachments))
	for _, att := range oldAttachments {
		if att.filter == nil {
			continue
		}
		currentAttachments[kernelAttachmentKeyForFilter(att.filter)] = att
	}
	plannedKeys := make([]kernelAttachmentKey, 0, len(plans))
	expected := make(map[kernelAttachmentKey]kernelAttachmentExpectation, len(plans))
	for _, plan := range plans {
		plannedKeys = append(plannedKeys, plan.key)
		expected[plan.key] = kernelAttachmentExpectationForPlan(plan)
	}
	observedAttachments := kernelAttachmentObservations(plannedKeys)

	newAttachments := make([]kernelAttachment, 0, len(plans))
	createdAttachments := make([]kernelAttachment, 0, len(plans))
	reattached := 0
	for _, plan := range plans {
		if current, ok := currentAttachments[plan.key]; ok && kernelAttachmentObservationMatchesExpectation(observedAttachments[plan.key], expected[plan.key]) {
			newAttachments = append(newAttachments, current)
			continue
		}
		if err := rt.attachProgramLocked(&createdAttachments, plan.ifindex, plan.key.parent, plan.priority, plan.handleMinor, plan.name, plan.prog); err != nil {
			rt.discardAttachmentsLocked(createdAttachments)
			return nil, fmt.Errorf("repair %s attachment on ifindex %d: %w", plan.name, plan.ifindex, err)
		}
		newAttachments = append(newAttachments, createdAttachments[len(createdAttachments)-1])
		reattached++
	}

	detached := kernelAttachmentDeleteCount(oldAttachments, newAttachments)
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	rt.attachments = newAttachments
	rt.maintenanceState.requestFull()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineTC, kernelHotRestartTCMetadata(rt.attachments, "")); err != nil {
			rt.stateLog.Logf("kernel dataplane self-heal: refreshed tc attachments but failed to update runtime metadata: %v", err)
		}
	}
	if reattached == 0 && detached == 0 {
		return nil, nil
	}
	rt.stateLog.Logf("kernel dataplane self-heal: repaired tc attachments reattach=%d detach=%d", reattached, detached)
	return []kernelAttachmentHealResult{{
		Engine:     kernelEngineTC,
		Reattached: reattached,
		Detached:   detached,
	}}, nil
}

func (rt *xdpKernelRuleRuntime) healAttachments() ([]kernelAttachmentHealResult, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.coll == nil || rt.coll.Maps == nil || len(rt.preparedRules) == 0 {
		return nil, nil
	}

	requiredIfIndices := collectXDPInterfaces(rt.preparedRules)
	if xdpAttachmentsHealthy(requiredIfIndices, rt.attachments, rt.programID) {
		return nil, nil
	}

	prog := rt.coll.Programs[kernelXDPProgramName]
	if prog == nil {
		return nil, fmt.Errorf("xdp object is missing program %q", kernelXDPProgramName)
	}
	if rt.programID == 0 {
		rt.programID = kernelProgramID(prog)
	}

	oldAttachments := append([]xdpAttachment(nil), rt.attachments...)
	currentAttachments := make(map[int]xdpAttachment, len(oldAttachments))
	for _, att := range oldAttachments {
		currentAttachments[att.ifindex] = att
	}

	newAttachments := make([]xdpAttachment, 0, len(requiredIfIndices))
	createdAttachments := make([]xdpAttachment, 0, len(requiredIfIndices))
	reattached := 0
	for _, ifindex := range requiredIfIndices {
		if current, ok := currentAttachments[ifindex]; ok && xdpAttachmentExists(current, rt.programID) {
			newAttachments = append(newAttachments, current)
			continue
		}
		att, err := rt.attachProgramLocked(ifindex, prog, prog, oldAttachments)
		if err != nil {
			rt.discardAttachmentsLocked(createdAttachments)
			return nil, fmt.Errorf("repair xdp attachment on ifindex %d: %w", ifindex, err)
		}
		createdAttachments = append(createdAttachments, att)
		newAttachments = append(newAttachments, att)
		reattached++
	}

	detached := xdpAttachmentDeleteCount(oldAttachments, newAttachments)
	rt.deleteStaleAttachmentsLocked(oldAttachments, newAttachments)
	rt.attachments = newAttachments
	rt.maintenanceState.requestFull()
	if len(rt.attachments) > 0 {
		if err := writeKernelRuntimeMetadata(kernelEngineXDP, kernelHotRestartXDPMetadata(rt.attachments, "")); err != nil {
			rt.stateLog.Logf("xdp dataplane self-heal: refreshed xdp attachments but failed to update runtime metadata: %v", err)
		}
	}
	if reattached == 0 && detached == 0 {
		return nil, nil
	}
	rt.stateLog.Logf("xdp dataplane self-heal: repaired xdp attachments reattach=%d detach=%d", reattached, detached)
	return []kernelAttachmentHealResult{{
		Engine:     kernelEngineXDP,
		Reattached: reattached,
		Detached:   detached,
	}}, nil
}

func (rt *orderedKernelRuleRuntime) healAttachments() ([]kernelAttachmentHealResult, error) {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	var out []kernelAttachmentHealResult
	for _, entry := range entries {
		healer, ok := entry.rt.(kernelAttachmentHealRuntime)
		if !ok || healer == nil {
			continue
		}
		items, err := healer.healAttachments()
		if err != nil {
			return out, fmt.Errorf("%s: %w", entry.name, err)
		}
		out = append(out, items...)
	}
	return out, nil
}

func xdpAttachmentDeleteCount(oldAttachments, newAttachments []xdpAttachment) int {
	if len(oldAttachments) == 0 {
		return 0
	}
	newIfIndices := make(map[int]struct{}, len(newAttachments))
	for _, att := range newAttachments {
		newIfIndices[att.ifindex] = struct{}{}
	}
	count := 0
	for _, att := range oldAttachments {
		if _, ok := newIfIndices[att.ifindex]; ok {
			continue
		}
		count++
	}
	return count
}
