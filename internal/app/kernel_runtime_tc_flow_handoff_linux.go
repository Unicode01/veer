//go:build linux

package app

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

type tcHotRestartTransparentFlowPath struct {
	ruleID       uint32
	childIfIndex uint32
}

type tcHotRestartTransparentFlowAlias struct {
	flows            *ebpf.Map
	mapName          string
	sourceKey        tcFlowKeyV4
	canonicalKey     tcFlowKeyV4
	canonicalCreated bool
}

type tcHotRestartTransparentFlowAliases struct {
	items []tcHotRestartTransparentFlowAlias
}

func tcHotRestartTransparentFlowParents(prepared []preparedKernelRule) map[tcHotRestartTransparentFlowPath]uint32 {
	parents := make(map[tcHotRestartTransparentFlowPath]uint32)
	for _, item := range prepared {
		if !item.rule.Transparent || kernelPreparedRuleFamily(item) != ipFamilyIPv4 {
			continue
		}
		ruleID := item.value.RuleID
		if ruleID == 0 && item.rule.ID > 0 && item.rule.ID <= int64(^uint32(0)) {
			ruleID = uint32(item.rule.ID)
		}
		parentIfIndex := preparedKernelRuleFlowOutIfIndex(item)
		if ruleID == 0 || parentIfIndex == 0 {
			continue
		}
		for _, mapping := range item.replyIfParents {
			if mapping.ifindex <= 0 || mapping.parentIfIndex <= 0 || uint32(mapping.parentIfIndex) != parentIfIndex {
				continue
			}
			childIfIndex := uint32(mapping.ifindex)
			if childIfIndex == parentIfIndex {
				continue
			}
			parents[tcHotRestartTransparentFlowPath{ruleID: ruleID, childIfIndex: childIfIndex}] = parentIfIndex
		}
	}
	return parents
}

func addTCHotRestartPredecessorFlowParents(parents map[tcHotRestartTransparentFlowPath]uint32, prepared []preparedKernelRule, attachments []kernelAttachment) {
	if len(parents) == 0 || len(attachments) == 0 {
		return
	}
	ruleParents := make(map[uint32]uint32)
	for _, item := range prepared {
		if !item.rule.Transparent || kernelPreparedRuleFamily(item) != ipFamilyIPv4 || item.value.RuleID == 0 {
			continue
		}
		if parentIfIndex := preparedKernelRuleFlowOutIfIndex(item); parentIfIndex != 0 {
			ruleParents[item.value.RuleID] = parentIfIndex
		}
	}
	for _, attachment := range attachments {
		filter := attachment.filter
		if filter == nil || filter.Priority != kernelReplyFilterPrio || filter.Handle != netlink.MakeHandle(0, kernelReplyFilterHandle) {
			continue
		}
		link, err := netlink.LinkByIndex(filter.LinkIndex)
		if err != nil {
			continue
		}
		mapping, ok := resolveTCBridgeParentMapping(link)
		if !ok {
			continue
		}
		for ruleID, parentIfIndex := range ruleParents {
			if uint32(mapping.parentIfIndex) == parentIfIndex {
				parents[tcHotRestartTransparentFlowPath{ruleID: ruleID, childIfIndex: uint32(mapping.ifindex)}] = parentIfIndex
			}
		}
	}
}

func stageTCHotRestartTransparentFlowAliases(coll *ebpf.Collection, prepared []preparedKernelRule, predecessorAttachments []kernelAttachment) (*tcHotRestartTransparentFlowAliases, error) {
	aliases := &tcHotRestartTransparentFlowAliases{}
	if coll == nil || coll.Maps == nil {
		return aliases, nil
	}
	parents := tcHotRestartTransparentFlowParents(prepared)
	addTCHotRestartPredecessorFlowParents(parents, prepared, predecessorAttachments)
	if len(parents) == 0 {
		return aliases, nil
	}

	// The predecessor continues using member keys until the successor hooks are
	// attached, so keep both forms only for the duration of the handoff.
	for _, current := range []struct {
		name  string
		flows *ebpf.Map
	}{
		{name: kernelFlowsMapName, flows: coll.Maps[kernelFlowsMapName]},
		{name: kernelTCFlowsOldMapNameV4, flows: coll.Maps[kernelTCFlowsOldMapNameV4]},
	} {
		if current.flows == nil {
			continue
		}
		candidates, err := collectTCHotRestartTransparentFlowAliases(current.name, current.flows, parents)
		if err != nil {
			_ = aliases.rollback()
			return nil, err
		}
		for _, candidate := range candidates {
			var existing tcFlowValueV4
			err := current.flows.Lookup(&candidate.canonicalKey, &existing)
			switch {
			case err == nil:
			case errors.Is(err, ebpf.ErrKeyNotExist):
				if err := current.flows.Update(&candidate.canonicalKey, &candidate.sourceValue, ebpf.UpdateNoExist); err != nil {
					_ = aliases.rollback()
					return nil, fmt.Errorf("stage legacy transparent flow alias in %s: %w", current.name, err)
				}
				candidate.canonicalCreated = true
			default:
				_ = aliases.rollback()
				return nil, fmt.Errorf("lookup canonical transparent flow key in %s: %w", current.name, err)
			}
			aliases.items = append(aliases.items, tcHotRestartTransparentFlowAlias{
				flows:            current.flows,
				mapName:          current.name,
				sourceKey:        candidate.sourceKey,
				canonicalKey:     candidate.canonicalKey,
				canonicalCreated: candidate.canonicalCreated,
			})
		}
	}
	return aliases, nil
}

type tcHotRestartTransparentFlowAliasCandidate struct {
	sourceKey        tcFlowKeyV4
	canonicalKey     tcFlowKeyV4
	sourceValue      tcFlowValueV4
	canonicalCreated bool
}

func collectTCHotRestartTransparentFlowAliases(mapName string, flows *ebpf.Map, parents map[tcHotRestartTransparentFlowPath]uint32) ([]tcHotRestartTransparentFlowAliasCandidate, error) {
	if flows == nil || len(parents) == 0 {
		return nil, nil
	}
	candidates := make([]tcHotRestartTransparentFlowAliasCandidate, 0)
	iter := flows.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		if value.RuleID == 0 || value.Flags&(kernelFlowFlagFullNAT|kernelFlowFlagFrontEntry|kernelFlowFlagEgressNAT) != 0 {
			continue
		}
		parentIfIndex, ok := parents[tcHotRestartTransparentFlowPath{ruleID: value.RuleID, childIfIndex: key.IfIndex}]
		if !ok || parentIfIndex == 0 || parentIfIndex == key.IfIndex {
			continue
		}
		canonicalKey := key
		canonicalKey.IfIndex = parentIfIndex
		candidates = append(candidates, tcHotRestartTransparentFlowAliasCandidate{
			sourceKey:    key,
			canonicalKey: canonicalKey,
			sourceValue:  value,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s for legacy transparent flow aliases: %w", mapName, err)
	}
	return candidates, nil
}

func mergeTCHotRestartTransparentFlowValues(canonical, source tcFlowValueV4) tcFlowValueV4 {
	if canonical.SessionID != source.SessionID {
		if source.LastSeenNS > canonical.LastSeenNS {
			return source
		}
		return canonical
	}
	merged := canonical
	merged.Flags |= source.Flags
	if source.LastSeenNS > merged.LastSeenNS {
		merged.LastSeenNS = source.LastSeenNS
	}
	if source.FrontCloseSeenNS > merged.FrontCloseSeenNS {
		merged.FrontCloseSeenNS = source.FrontCloseSeenNS
	}
	return merged
}

func (aliases *tcHotRestartTransparentFlowAliases) finalize() (int, error) {
	if aliases == nil {
		return 0, nil
	}
	finalized := 0
	var errs []error
	for _, item := range aliases.items {
		var source tcFlowValueV4
		if err := item.flows.Lookup(&item.sourceKey, &source); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if item.canonicalCreated {
					if deleteErr := item.flows.Delete(&item.canonicalKey); deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
						errs = append(errs, fmt.Errorf("delete staged alias for closed transparent flow in %s: %w", item.mapName, deleteErr))
						continue
					}
					finalized++
				}
			} else {
				errs = append(errs, fmt.Errorf("lookup legacy transparent flow key in %s: %w", item.mapName, err))
			}
			continue
		}

		var canonical tcFlowValueV4
		if err := item.flows.Lookup(&item.canonicalKey, &canonical); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("lookup staged transparent flow key in %s: %w", item.mapName, err))
				continue
			}
			if err := item.flows.Delete(&item.sourceKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("delete closed legacy transparent flow key in %s: %w", item.mapName, err))
				continue
			}
			finalized++
			continue
		}

		merged := mergeTCHotRestartTransparentFlowValues(canonical, source)
		if err := item.flows.Update(&item.canonicalKey, &merged, ebpf.UpdateExist); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if deleteErr := item.flows.Delete(&item.sourceKey); deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
					errs = append(errs, fmt.Errorf("delete closed legacy transparent flow key in %s: %w", item.mapName, deleteErr))
					continue
				}
				finalized++
				continue
			}
			errs = append(errs, fmt.Errorf("merge legacy transparent flow alias in %s: %w", item.mapName, err))
			continue
		}
		if err := item.flows.Delete(&item.sourceKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete legacy transparent flow key in %s: %w", item.mapName, err))
			continue
		}
		finalized++
	}
	aliases.items = nil
	return finalized, errors.Join(errs...)
}

func (aliases *tcHotRestartTransparentFlowAliases) rollback() error {
	if aliases == nil {
		return nil
	}
	var errs []error
	for i := len(aliases.items) - 1; i >= 0; i-- {
		item := aliases.items[i]
		if !item.canonicalCreated {
			continue
		}
		if err := item.flows.Delete(&item.canonicalKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("rollback transparent flow alias in %s: %w", item.mapName, err))
		}
	}
	aliases.items = nil
	return errors.Join(errs...)
}
