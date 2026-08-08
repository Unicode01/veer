package app

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
)

type kernelCandidateIdentity struct {
	kind               string
	ownerID            int64
	ownerKey           string
	inInterface        string
	inIP               string
	inPort             int
	outInterface       string
	outIP              string
	outSourceIP        string
	outPort            int
	protocol           string
	transparent        bool
	kernelMode         string
	kernelNATType      string
	kernelRedirectMode string
}

func validKernelDataplaneRuleID(id int64) bool {
	return id > 0 && id <= int64(math.MaxUint32)
}

func kernelRuleStableOwnerMatches(a, b Rule) bool {
	leftKey := strings.TrimSpace(a.kernelOwnerKey)
	rightKey := strings.TrimSpace(b.kernelOwnerKey)
	if leftKey != "" || rightKey != "" {
		return leftKey != "" && leftKey == rightKey
	}
	return kernelRuleLogOwnerID(a) == kernelRuleLogOwnerID(b)
}

func kernelCandidateIdentityFor(item kernelCandidateRule) kernelCandidateIdentity {
	ownerID := item.owner.id
	ownerKey := strings.TrimSpace(item.rule.kernelOwnerKey)
	if ownerKey != "" {
		ownerID = 0
	}
	rule := item.rule
	return kernelCandidateIdentity{
		kind:               item.owner.kind,
		ownerID:            ownerID,
		ownerKey:           ownerKey,
		inInterface:        rule.InInterface,
		inIP:               rule.InIP,
		inPort:             rule.InPort,
		outInterface:       rule.OutInterface,
		outIP:              rule.OutIP,
		outSourceIP:        rule.OutSourceIP,
		outPort:            rule.OutPort,
		protocol:           rule.Protocol,
		transparent:        rule.Transparent,
		kernelMode:         rule.kernelMode,
		kernelNATType:      rule.kernelNATType,
		kernelRedirectMode: rule.kernelRedirectMode,
	}
}

func kernelCandidateIdentityForRule(rule Rule) kernelCandidateIdentity {
	return kernelCandidateIdentityFor(kernelCandidateRule{
		owner: kernelCandidateOwner{
			kind: kernelRuleLogKind(rule),
			id:   kernelRuleLogOwnerID(rule),
		},
		rule: rule,
	})
}

func snapshotKernelCandidateRules(runtime kernelRuleRuntime) []Rule {
	if runtime == nil {
		return nil
	}
	snapshotter, ok := runtime.(kernelRuleIDSnapshotRuntime)
	if !ok || snapshotter == nil {
		return nil
	}
	return snapshotter.snapshotKernelCandidateRules()
}

func stabilizeKernelCandidateRuleIDs(candidates []kernelCandidateRule, previous []Rule) error {
	if len(candidates) == 0 {
		return nil
	}

	desiredByIdentity := make(map[kernelCandidateIdentity][]int, len(candidates))
	identities := make([]kernelCandidateIdentity, len(candidates))
	for idx, candidate := range candidates {
		identity := kernelCandidateIdentityFor(candidate)
		identities[idx] = identity
		desiredByIdentity[identity] = append(desiredByIdentity[identity], idx)
	}

	reserved := make(map[uint32]struct{}, len(previous)+len(candidates))
	previousByID := make(map[uint32]kernelCandidateIdentity, len(previous))
	previousIDs := make([]uint32, 0, len(previous))
	for _, rule := range previous {
		if !validKernelDataplaneRuleID(rule.ID) {
			continue
		}
		id := uint32(rule.ID)
		reserved[id] = struct{}{}
		if _, exists := previousByID[id]; exists {
			continue
		}
		previousByID[id] = kernelCandidateIdentityForRule(rule)
		previousIDs = append(previousIDs, id)
	}
	sort.Slice(previousIDs, func(i, j int) bool { return previousIDs[i] < previousIDs[j] })

	assigned := make([]bool, len(candidates))
	for _, id := range previousIDs {
		identity := previousByID[id]
		for _, idx := range desiredByIdentity[identity] {
			if assigned[idx] {
				continue
			}
			candidates[idx].rule.ID = int64(id)
			assigned[idx] = true
			break
		}
	}

	primary := make([]int, 0, len(candidates))
	for idx, candidate := range candidates {
		if assigned[idx] || candidate.owner.kind != workerKindRule || strings.TrimSpace(candidate.rule.kernelOwnerKey) != "" || candidate.rule.ID != candidate.owner.id || !validKernelDataplaneRuleID(candidate.owner.id) {
			continue
		}
		primary = append(primary, idx)
	}
	sort.Slice(primary, func(i, j int) bool {
		return candidates[primary[i]].owner.id < candidates[primary[j]].owner.id
	})
	for _, idx := range primary {
		id := uint32(candidates[idx].owner.id)
		if _, occupied := reserved[id]; occupied {
			continue
		}
		reserved[id] = struct{}{}
		candidates[idx].rule.ID = int64(id)
		assigned[idx] = true
	}

	if len(previousIDs) == 0 {
		for idx, candidate := range candidates {
			if assigned[idx] || !validKernelDataplaneRuleID(candidate.rule.ID) {
				continue
			}
			id := uint32(candidate.rule.ID)
			if _, occupied := reserved[id]; occupied {
				continue
			}
			reserved[id] = struct{}{}
			assigned[idx] = true
		}
	}

	remaining := make([]int, 0, len(candidates))
	for idx := range candidates {
		if !assigned[idx] {
			remaining = append(remaining, idx)
		}
	}
	sort.SliceStable(remaining, func(i, j int) bool {
		return compareKernelCandidateIdentity(identities[remaining[i]], identities[remaining[j]]) < 0
	})
	for _, idx := range remaining {
		id, err := allocateStableKernelCandidateRuleID(identities[idx], reserved)
		if err != nil {
			return err
		}
		reserved[id] = struct{}{}
		candidates[idx].rule.ID = int64(id)
		assigned[idx] = true
	}
	return nil
}

func compareKernelCandidateIdentity(a, b kernelCandidateIdentity) int {
	left := kernelCandidateIdentitySortKey(a)
	right := kernelCandidateIdentitySortKey(b)
	return strings.Compare(left, right)
}

func kernelCandidateIdentitySortKey(identity kernelCandidateIdentity) string {
	return fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s\x00%s\x00%d\x00%s\x00%t\x00%s\x00%s\x00%s",
		identity.kind,
		identity.ownerID,
		identity.ownerKey,
		identity.inInterface,
		identity.inIP,
		identity.inPort,
		identity.outInterface,
		identity.outIP,
		identity.outSourceIP,
		identity.outPort,
		identity.protocol,
		identity.transparent,
		identity.kernelMode,
		identity.kernelNATType,
		identity.kernelRedirectMode,
	)
}

func allocateStableKernelCandidateRuleID(identity kernelCandidateIdentity, occupied map[uint32]struct{}) (uint32, error) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(kernelCandidateIdentitySortKey(identity)))
	sum := h.Sum64()
	id := uint32(sum)
	if id == 0 {
		id = 1
	}
	step := uint32(sum>>32) | 1
	for attempts := uint64(0); attempts < uint64(math.MaxUint32); attempts++ {
		if _, exists := occupied[id]; !exists {
			return id, nil
		}
		id += step
		if id == 0 {
			id += step
		}
	}
	return 0, fmt.Errorf("kernel dataplane rule id space exhausted")
}
