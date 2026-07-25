package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type pluginPackagePublisherApproval struct {
	stage   PluginPackageStage
	request PluginPackageApplyRequest
}

type pluginPackagePublisherTrustDraft struct {
	name        string
	publicKey   string
	pluginIDs   map[string]struct{}
	permissions map[string]struct{}
	tiers       map[string]struct{}
	stabilities map[string]struct{}
}

func (m *pluginPackageManager) validatePluginPackageSourceApproval(stage PluginPackageStage, request PluginPackageApplyRequest) error {
	if stage.TrustSource == "history" || stage.TrustSource == "tuf" {
		if request.RememberPublisher {
			return fmt.Errorf("verified history and repository packages do not have a local publisher to remember")
		}
		return nil
	}
	if !stage.Signed {
		if m.cfg.PluginsRequireSignedPackages() {
			return fmt.Errorf("plugin package is unsigned and plugins_require_signed_packages is enabled")
		}
		if !request.ApproveUnsigned {
			return fmt.Errorf("plugin package is unsigned; explicit approve_unsigned confirmation is required")
		}
		if request.RememberPublisher {
			return fmt.Errorf("an unsigned plugin package has no publisher to remember")
		}
		return nil
	}
	if !stage.Trusted && !request.ApprovePublisher {
		return fmt.Errorf("plugin package publisher is %s; explicit approve_publisher confirmation is required", stage.PublisherStatus)
	}
	if request.RememberPublisher && !stage.Trusted && stage.PublisherStatus != pluginPackagePublisherUnknown {
		return fmt.Errorf("plugin publisher in state %s cannot be remembered from the install flow", stage.PublisherStatus)
	}
	return nil
}

func (m *pluginPackageManager) rememberPluginPackagePublishers(items []pluginPackagePublisherApproval) ([]PluginTrustKey, error) {
	drafts := make(map[string]*pluginPackagePublisherTrustDraft)
	for _, item := range items {
		stage := item.stage
		if !item.request.RememberPublisher || stage.Trusted {
			continue
		}
		if !stage.Signed || stage.PublisherStatus != pluginPackagePublisherUnknown || len(stage.SignerID) != 32 || stage.SignerPublicKey == "" {
			return nil, fmt.Errorf("plugin %s does not have an unknown verified publisher that can be remembered", stage.PluginID)
		}
		draft := drafts[stage.SignerID]
		if draft == nil {
			draft = &pluginPackagePublisherTrustDraft{
				name: stage.PluginID + " / " + stage.SignerID[:8], publicKey: stage.SignerPublicKey,
				pluginIDs: make(map[string]struct{}), permissions: make(map[string]struct{}),
				tiers: make(map[string]struct{}), stabilities: make(map[string]struct{}),
			}
			drafts[stage.SignerID] = draft
		} else if draft.publicKey != stage.SignerPublicKey {
			return nil, fmt.Errorf("publisher %s uses inconsistent public keys in the batch", stage.SignerID)
		}
		draft.pluginIDs[stage.PluginID] = struct{}{}
		for _, permission := range stage.Permissions {
			draft.permissions[permission] = struct{}{}
		}
		draft.tiers[stage.ExecutionTier] = struct{}{}
		draft.stabilities[stage.Stability] = struct{}{}
	}

	ids := make([]string, 0, len(drafts))
	for id := range drafts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	created := make([]PluginTrustKey, 0, len(ids))
	for _, id := range ids {
		draft := drafts[id]
		key, err := m.AddTrustKey(PluginTrustKeyRequest{
			Name:      draft.name,
			PublicKey: draft.publicKey,
			Scope: &PluginTrustScope{
				PluginIDs:             sortedPluginPackagePublisherValues(draft.pluginIDs),
				Permissions:           sortedPluginPackagePublisherValues(draft.permissions),
				PermissionsRestricted: true,
				ExecutionTiers:        sortedPluginPackagePublisherValues(draft.tiers),
				Stabilities:           sortedPluginPackagePublisherValues(draft.stabilities),
			},
		})
		if err != nil {
			m.rollbackRememberedPluginPublishers(created, "trust creation failed: "+err.Error())
			return nil, err
		}
		created = append(created, key)
	}
	return created, nil
}

func (m *pluginPackageManager) rollbackRememberedPluginPublishers(keys []PluginTrustKey, reason string) {
	for i := len(keys) - 1; i >= 0; i-- {
		created := keys[i]
		id := strings.TrimSpace(strings.ToLower(created.ID))
		if len(id) != 32 {
			continue
		}
		current, err := m.loadPluginTrustKey(id)
		if err != nil {
			if !os.IsNotExist(err) {
				recordPluginAudit(m.db, "", "trust.install_rollback", "system", "error", map[string]any{
					"key_id": id, "reason": reason, "error": err.Error(),
				})
			}
			continue
		}
		if !equalPluginTrustKeys(current, created) {
			recordPluginAudit(m.db, "", "trust.install_rollback", "system", "error", map[string]any{
				"key_id": id, "reason": reason, "error": "trust key changed during plugin apply",
			})
			continue
		}
		path := filepath.Join(m.stateRoot, "trust", id+".json")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			recordPluginAudit(m.db, "", "trust.install_rollback", "system", "error", map[string]any{
				"key_id": id, "reason": reason, "error": err.Error(),
			})
			continue
		}
		recordPluginAudit(m.db, "", "trust.install_rollback", "system", "success", map[string]any{
			"key_id": id, "reason": reason,
		})
	}
}

func sortedPluginPackagePublisherValues(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value = strings.TrimSpace(strings.ToLower(value)); value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
