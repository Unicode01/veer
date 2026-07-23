package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (m *pluginPackageManager) ListProbationGroups() ([]PluginPackageProbationGroup, error) {
	root := filepath.Join(m.stateRoot, "probation-groups")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []PluginPackageProbationGroup{}, nil
	}
	if err != nil {
		return nil, err
	}
	groups := make([]PluginPackageProbationGroup, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != pluginPackageProbationGroupFileSuffix {
			continue
		}
		groupID := strings.TrimSuffix(entry.Name(), pluginPackageProbationGroupFileSuffix)
		if validatePluginPackageID(groupID) != nil {
			return nil, fmt.Errorf("invalid plugin probation group file %q", entry.Name())
		}
		var group PluginPackageProbationGroup
		if err := readPluginPackageJSON(filepath.Join(root, entry.Name()), &group); err != nil {
			return nil, fmt.Errorf("read plugin probation group %s: %w", groupID, err)
		}
		if err := validatePluginPackageProbationGroup(group); err != nil {
			return nil, fmt.Errorf("validate plugin probation group %s: %w", groupID, err)
		}
		if group.ID != groupID {
			return nil, fmt.Errorf("plugin probation group file identity mismatch for %s", groupID)
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func (m *pluginPackageManager) loadPluginPackageProbationGroup(groupID string) (PluginPackageProbationGroup, error) {
	groupID = strings.TrimSpace(strings.ToLower(groupID))
	if validatePluginPackageID(groupID) != nil {
		return PluginPackageProbationGroup{}, fmt.Errorf("invalid plugin probation group id")
	}
	var group PluginPackageProbationGroup
	if err := readPluginPackageJSON(m.pluginPackageProbationGroupPath(groupID), &group); err != nil {
		return PluginPackageProbationGroup{}, err
	}
	if err := validatePluginPackageProbationGroup(group); err != nil {
		return PluginPackageProbationGroup{}, err
	}
	if group.ID != groupID {
		return PluginPackageProbationGroup{}, fmt.Errorf("plugin probation group identity mismatch")
	}
	return group, nil
}

func (m *pluginPackageManager) ensurePluginPackageProbationGroup(group PluginPackageProbationGroup) (PluginPackageProbationGroup, error) {
	if err := validatePluginPackageProbationGroup(group); err != nil {
		return PluginPackageProbationGroup{}, err
	}
	existing, err := m.loadPluginPackageProbationGroup(group.ID)
	if err == nil {
		if !equalPluginPackageProbationGroups(existing, group) {
			return PluginPackageProbationGroup{}, fmt.Errorf("plugin probation group %s no longer matches its batch", group.ID)
		}
		return existing, nil
	}
	if !os.IsNotExist(err) {
		return PluginPackageProbationGroup{}, err
	}
	if err := m.writePluginPackageProbationGroup(group); err != nil {
		return PluginPackageProbationGroup{}, err
	}
	return group, nil
}

func (m *pluginPackageManager) writePluginPackageProbationGroup(group PluginPackageProbationGroup) error {
	if err := validatePluginPackageProbationGroup(group); err != nil {
		return err
	}
	return writePluginPackageJSONAtomic(m.pluginPackageProbationGroupPath(group.ID), group, true)
}

func (m *pluginPackageManager) removePluginPackageProbationGroup(groupID string) error {
	if validatePluginPackageID(groupID) != nil {
		return fmt.Errorf("invalid plugin probation group id")
	}
	if err := os.Remove(m.pluginPackageProbationGroupPath(groupID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *pluginPackageManager) pluginPackageProbationGroupPath(groupID string) string {
	return filepath.Join(m.stateRoot, "probation-groups", groupID+pluginPackageProbationGroupFileSuffix)
}

func validatePluginPackageProbationGroup(group PluginPackageProbationGroup) error {
	if validatePluginPackageID(group.ID) != nil {
		return fmt.Errorf("invalid group id")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, group.CreatedAt)
	if err != nil || createdAt.IsZero() {
		return fmt.Errorf("invalid group creation time")
	}
	if len(group.Members) == 0 || len(group.Members) > pluginPackageBatchMaxStages {
		return fmt.Errorf("invalid group member count")
	}
	previousID := ""
	for _, member := range group.Members {
		if !pluginIDPattern.MatchString(member.PluginID) || reservedBuiltinPluginID(member.PluginID) || member.PluginID <= previousID {
			return fmt.Errorf("group members must have unique sorted plugin ids")
		}
		previousID = member.PluginID
		if normalized, versionErr := normalizePluginSemanticVersion(member.Version); versionErr != nil || normalized != member.Version {
			return fmt.Errorf("invalid member version for %s", member.PluginID)
		}
		switch member.Operation {
		case "install":
			if member.PreviousHistoryID != "" {
				return fmt.Errorf("installed member %s cannot have rollback history", member.PluginID)
			}
		case "update", "rollback":
			if !validPluginPackageHistoryID(member.PreviousHistoryID) {
				return fmt.Errorf("replaced member %s is missing rollback history", member.PluginID)
			}
		default:
			return fmt.Errorf("invalid member operation %q", member.Operation)
		}
	}
	if group.RecoveryAttempts < 0 {
		return fmt.Errorf("invalid group recovery attempts")
	}
	if group.NextRecoveryAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, group.NextRecoveryAt); err != nil {
			return fmt.Errorf("invalid group recovery time")
		}
	}
	if group.LastFailureAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, group.LastFailureAt); err != nil {
			return fmt.Errorf("invalid group failure time")
		}
	}
	if len(group.LastFailure) > pluginControlMaxLogMessageBytes {
		return fmt.Errorf("group failure message is too large")
	}
	return nil
}

func equalPluginPackageProbationGroups(left, right PluginPackageProbationGroup) bool {
	if left.ID != right.ID || left.CreatedAt != right.CreatedAt || len(left.Members) != len(right.Members) {
		return false
	}
	for i := range left.Members {
		if left.Members[i] != right.Members[i] {
			return false
		}
	}
	return true
}

func (m *pluginPackageManager) ensurePluginPackageMutationAllowed(pluginIDs []string) error {
	if m == nil || m.probationRecovery {
		return nil
	}
	requested := make(map[string]struct{}, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		pluginID = strings.TrimSpace(strings.ToLower(pluginID))
		if pluginID != "" {
			requested[pluginID] = struct{}{}
		}
	}
	groups, err := m.ListProbationGroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		for _, member := range group.Members {
			if _, exists := requested[member.PluginID]; exists {
				return fmt.Errorf("plugin %s is still in package probation group %s; wait for the group to pass or recover", member.PluginID, group.ID)
			}
		}
	}
	return nil
}

func (m *pluginPackageManager) recoverPluginPackageProbationGroups() error {
	groups, err := m.ListProbationGroups()
	if err != nil {
		return err
	}
	records, err := m.ListProbations()
	if err != nil {
		return err
	}
	groupsByID := make(map[string]PluginPackageProbationGroup, len(groups))
	recordCount := make(map[string]int, len(groups))
	for _, group := range groups {
		groupsByID[group.ID] = group
	}
	for _, record := range records {
		if record.GroupID == "" {
			continue
		}
		group, exists := groupsByID[record.GroupID]
		if !exists {
			return fmt.Errorf("plugin probation %s references missing group %s", record.PluginID, record.GroupID)
		}
		matched := false
		for _, member := range group.Members {
			if member.PluginID == record.PluginID && member.Version == record.Version && member.PreviousHistoryID == record.PreviousHistoryID {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("plugin probation %s does not match group %s", record.PluginID, record.GroupID)
		}
		recordCount[record.GroupID]++
	}
	for _, group := range groups {
		if recordCount[group.ID] != 0 {
			continue
		}
		if err := m.removePluginPackageProbationGroup(group.ID); err != nil {
			return err
		}
		recordPluginAudit(m.db, "", "package.probation_group_passed", "system", "success", map[string]any{
			"group_id": group.ID, "plugin_ids": pluginPackageProbationGroupIDs(group), "reason": "completed before group cleanup",
		})
	}
	return nil
}

func (m *pluginPackageManager) removePluginPackageProbationGroupState(group PluginPackageProbationGroup) error {
	for _, member := range group.Members {
		if err := m.removePluginPackageProbation(member.PluginID); err != nil {
			return err
		}
	}
	return m.removePluginPackageProbationGroup(group.ID)
}

func (m *pluginPackageManager) completePluginPackageProbationGroupIfFinished(groupID, reason string) error {
	if groupID == "" {
		return nil
	}
	group, err := m.loadPluginPackageProbationGroup(groupID)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	records, err := m.ListProbations()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.GroupID == groupID {
			return nil
		}
	}
	if err := m.removePluginPackageProbationGroup(groupID); err != nil {
		return err
	}
	recordPluginAudit(m.db, "", "package.probation_group_passed", "system", "success", map[string]any{
		"group_id": group.ID, "plugin_ids": pluginPackageProbationGroupIDs(group), "reason": reason,
	})
	return nil
}

func (m *pluginPackageManager) notePluginPackageProbationGroupRecoveryFailure(group *PluginPackageProbationGroup, reason string, recoveryErr error) error {
	if group == nil {
		return nil
	}
	group.RecoveryAttempts++
	group.LastFailure = boundedPluginControlHealthError(reason + "; recovery: " + recoveryErr.Error())
	now := time.Now().UTC()
	group.LastFailureAt = now.Format(time.RFC3339Nano)
	delay := time.Minute << min(group.RecoveryAttempts-1, 3)
	group.NextRecoveryAt = now.Add(delay).Format(time.RFC3339Nano)
	if err := m.writePluginPackageProbationGroup(*group); err != nil {
		return err
	}
	for _, member := range group.Members {
		record, err := m.loadPluginPackageProbation(member.PluginID)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if record.GroupID != group.ID {
			return fmt.Errorf("plugin probation %s no longer belongs to group %s", member.PluginID, group.ID)
		}
		record.RecoveryAttempts = group.RecoveryAttempts
		record.NextRecoveryAt = group.NextRecoveryAt
		record.LastFailure = group.LastFailure
		record.LastFailureAt = group.LastFailureAt
		if err := m.writePluginPackageProbation(record); err != nil {
			return err
		}
	}
	return nil
}

func pluginPackageProbationGroupIDs(group PluginPackageProbationGroup) []string {
	ids := make([]string, 0, len(group.Members))
	for _, member := range group.Members {
		ids = append(ids, member.PluginID)
	}
	return ids
}
