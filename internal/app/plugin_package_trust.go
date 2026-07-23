package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type pluginPackageManager struct {
	cfg                  *Config
	db                   *sql.DB
	pm                   *ProcessManager
	pluginsRoot          string
	stateRoot            string
	runtimeApply         func(string) (bool, error)
	runtimeApplyBatch    func([]string) (bool, error)
	batchFault           func(string) error
	suppressProbation    bool
	probationRecovery    bool
	repositoryHTTPClient *http.Client
}

const (
	pluginTrustStatusActive  = "active"
	pluginTrustStatusRevoked = "revoked"
	pluginTrustScopeMaxItems = 128
)

func newPluginPackageManager(cfg *Config, db *sql.DB, pm *ProcessManager) (*pluginPackageManager, error) {
	pluginsDir := normalizePluginsDir("")
	if cfg != nil {
		pluginsDir = normalizePluginsDir(cfg.PluginsDir)
	}
	absPlugins, err := filepath.Abs(pluginsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugins directory: %w", err)
	}
	if err := ensurePluginPackageDirectory(absPlugins, 0o700); err != nil {
		return nil, fmt.Errorf("prepare plugins directory: %w", err)
	}
	realPlugins, err := filepath.EvalSymlinks(absPlugins)
	if err != nil {
		return nil, fmt.Errorf("resolve plugins directory: %w", err)
	}
	if realPlugins != absPlugins {
		return nil, fmt.Errorf("managed plugin installation requires plugins_dir itself not to be a symbolic link")
	}
	stateRoot := realPlugins + pluginPackageStateSuffix
	for _, dir := range []string{
		stateRoot,
		filepath.Join(stateRoot, "staging"),
		filepath.Join(stateRoot, "history"),
		filepath.Join(stateRoot, "transactions"),
		filepath.Join(stateRoot, "batches"),
		filepath.Join(stateRoot, "trust"),
		filepath.Join(stateRoot, "trust-rotations"),
		filepath.Join(stateRoot, "probation"),
		filepath.Join(stateRoot, "probation-groups"),
		filepath.Join(stateRoot, "repositories"),
		filepath.Join(stateRoot, "repository-policies"),
		filepath.Join(stateRoot, "provenance"),
	} {
		if err := ensurePluginPackageDirectory(dir, 0o700); err != nil {
			return nil, fmt.Errorf("prepare plugin package state: %w", err)
		}
	}
	manager := &pluginPackageManager{cfg: cfg, db: db, pm: pm, pluginsRoot: realPlugins, stateRoot: stateRoot}
	if err := manager.recoverPluginTrustRotations(); err != nil {
		return nil, err
	}
	if err := manager.recoverBatchTransactions(); err != nil {
		return nil, err
	}
	if err := manager.recoverTransactions(); err != nil {
		return nil, err
	}
	if err := manager.recoverPluginPackageProbationGroups(); err != nil {
		return nil, err
	}
	manager.cleanupExpiredStages(time.Now())
	return manager, nil
}

func recoverPluginPackageStateIfPresent(cfg *Config, db *sql.DB) error {
	pluginsDir := normalizePluginsDir("")
	if cfg != nil {
		pluginsDir = normalizePluginsDir(cfg.PluginsDir)
	}
	absPlugins, err := filepath.Abs(pluginsDir)
	if err != nil {
		return err
	}
	stateRoot := absPlugins + pluginPackageStateSuffix
	if _, err := os.Lstat(stateRoot); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	manager, err := newPluginPackageManager(cfg, db, nil)
	if err != nil {
		return err
	}
	return manager.recoverPluginPackageProbationsOnStartup(time.Now())
}

func ensurePluginPackageDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path) // #nosec G703 -- every caller constructs this path below a private manager-owned root from validated identifiers.
	if os.IsNotExist(err) {
		return os.MkdirAll(path, mode)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a regular directory", path)
	}
	return os.Chmod(path, mode)
}

func (m *pluginPackageManager) AddTrustKey(request PluginTrustKeyRequest) (PluginTrustKey, error) {
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return PluginTrustKey{}, fmt.Errorf("trust key name must contain 1 to 128 printable characters")
	}
	publicKey, err := decodePluginTrustPublicKey(request.PublicKey)
	if err != nil {
		return PluginTrustKey{}, err
	}
	id := pluginTrustKeyID(publicKey)
	scope, err := normalizePluginTrustScope(request.Scope)
	if err != nil {
		return PluginTrustKey{}, err
	}
	replaces := strings.TrimSpace(strings.ToLower(request.Replaces))
	if replaces != "" {
		if replaces == id || len(replaces) != 32 {
			return PluginTrustKey{}, fmt.Errorf("replacement trust key id is invalid")
		}
		oldKey, loadErr := m.loadPluginTrustKey(replaces)
		if loadErr != nil {
			return PluginTrustKey{}, loadErr
		}
		if request.Scope == nil {
			scope = clonePluginTrustScope(oldKey.Scope)
		} else if !pluginTrustScopeContains(oldKey.Scope, scope) {
			return PluginTrustKey{}, fmt.Errorf("replacement trust scope cannot be broader than the active key")
		}
	}
	key := PluginTrustKey{
		ID:        id,
		Name:      name,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Status:    pluginTrustStatusActive,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Scope:     scope,
	}
	path := filepath.Join(m.stateRoot, "trust", id+".json")
	if _, err := os.Lstat(path); err == nil {
		return PluginTrustKey{}, fmt.Errorf("trust key %s already exists", id)
	} else if !os.IsNotExist(err) {
		return PluginTrustKey{}, err
	}
	if replaces != "" {
		if err := m.rotatePluginTrustKey(replaces, key); err != nil {
			return PluginTrustKey{}, fmt.Errorf("rotate trust key: %w", err)
		}
	} else if err := writePluginPackageJSONAtomic(path, key, false); err != nil {
		return PluginTrustKey{}, err
	}
	recordPluginAudit(m.db, "", "trust.add", "system", "success", map[string]any{
		"key_id": key.ID, "name": key.Name, "replaces": replaces, "scope": key.Scope,
	})
	return key, nil
}

func (m *pluginPackageManager) ListTrustKeys() ([]PluginTrustKey, error) {
	dir := filepath.Join(m.stateRoot, "trust")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	keys := make([]PluginTrustKey, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		var key PluginTrustKey
		if err := readPluginPackageJSON(filepath.Join(dir, entry.Name()), &key); err != nil {
			return nil, fmt.Errorf("read trust key %s: %w", entry.Name(), err)
		}
		publicKey, err := decodePluginTrustPublicKey(key.PublicKey)
		if key.Status == "" {
			key.Status = pluginTrustStatusActive
		}
		if err != nil || pluginTrustKeyID(publicKey) != key.ID || entry.Name() != key.ID+".json" || validatePluginTrustKeyState(key) != nil {
			return nil, fmt.Errorf("trust key %s failed integrity validation", entry.Name())
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	return keys, nil
}

func (m *pluginPackageManager) DeleteTrustKey(id string) error {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) != 32 {
		return fmt.Errorf("invalid trust key id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("invalid trust key id")
	}
	if err := m.revokeTrustKey(id, ""); err != nil {
		return err
	}
	recordPluginAudit(m.db, "", "trust.revoke", "system", "success", map[string]any{"key_id": id})
	return nil
}

func (m *pluginPackageManager) revokeTrustKey(id, replacedBy string) error {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) != 32 {
		return fmt.Errorf("invalid trust key id")
	}
	path := filepath.Join(m.stateRoot, "trust", id+".json")
	var key PluginTrustKey
	if err := readPluginPackageJSON(path, &key); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("trust key %s not found", id)
		}
		return err
	}
	if key.Status == "" {
		key.Status = pluginTrustStatusActive
	}
	if err := validatePluginTrustKeyState(key); err != nil {
		return err
	}
	if key.Status == pluginTrustStatusRevoked {
		return fmt.Errorf("trust key %s is already revoked", id)
	}
	if replacedBy != "" {
		if len(replacedBy) != 32 || replacedBy == id {
			return fmt.Errorf("replacement trust key id is invalid")
		}
		key.ReplacedBy = replacedBy
	}
	key.Status = pluginTrustStatusRevoked
	key.RevokedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writePluginPackageJSONAtomic(path, key, true)
}

func validatePluginTrustKeyState(key PluginTrustKey) error {
	if key.Status != pluginTrustStatusActive && key.Status != pluginTrustStatusRevoked {
		return fmt.Errorf("trust key %s has invalid status", key.ID)
	}
	if _, err := time.Parse(time.RFC3339Nano, key.CreatedAt); err != nil {
		return fmt.Errorf("trust key %s has invalid creation time", key.ID)
	}
	normalizedScope, err := normalizePluginTrustScope(key.Scope)
	if err != nil || !equalPluginTrustScopes(normalizedScope, key.Scope) {
		return fmt.Errorf("trust key %s has invalid scope", key.ID)
	}
	if key.Status == pluginTrustStatusActive {
		if key.RevokedAt != "" || key.ReplacedBy != "" {
			return fmt.Errorf("active trust key %s contains revocation metadata", key.ID)
		}
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, key.RevokedAt); err != nil {
		return fmt.Errorf("revoked trust key %s has invalid revocation time", key.ID)
	}
	if key.ReplacedBy != "" && len(key.ReplacedBy) != 32 {
		return fmt.Errorf("revoked trust key %s has invalid replacement", key.ID)
	}
	return nil
}

func normalizePluginTrustScope(scope *PluginTrustScope) (*PluginTrustScope, error) {
	if scope == nil {
		return nil, nil
	}
	if len(scope.PluginIDs) > pluginTrustScopeMaxItems || len(scope.Permissions) > pluginTrustScopeMaxItems ||
		len(scope.ExecutionTiers) > pluginTrustScopeMaxItems || len(scope.Stabilities) > pluginTrustScopeMaxItems {
		return nil, fmt.Errorf("trust scope exceeds %d entries per field", pluginTrustScopeMaxItems)
	}
	pluginIDs := make([]string, 0, len(scope.PluginIDs))
	seenPluginIDs := make(map[string]struct{}, len(scope.PluginIDs))
	for _, raw := range scope.PluginIDs {
		pattern := strings.TrimSpace(strings.ToLower(raw))
		if pattern == "" {
			continue
		}
		base := strings.TrimSuffix(pattern, "*")
		if base == "" || !pluginIDPattern.MatchString(base) || strings.Count(pattern, "*") > 1 ||
			(strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
			return nil, fmt.Errorf("trust scope plugin id %q must be an exact plugin id or a trailing-prefix pattern", pattern)
		}
		if _, exists := seenPluginIDs[pattern]; exists {
			continue
		}
		seenPluginIDs[pattern] = struct{}{}
		pluginIDs = append(pluginIDs, pattern)
	}
	permissions, err := normalizePluginTokens(scope.Permissions, "trust scope permission")
	if err != nil {
		return nil, err
	}
	executionTiers, err := normalizePluginTrustEnum(scope.ExecutionTiers, "execution tier", map[string]struct{}{
		pluginPackageExecutionTierControl: {}, pluginPackageExecutionTierDataplane: {},
	})
	if err != nil {
		return nil, err
	}
	stabilities, err := normalizePluginTrustEnum(scope.Stabilities, "stability", map[string]struct{}{
		pluginStabilityStable: {}, pluginStabilityPreview: {}, pluginStabilityLab: {}, pluginStabilityDeprecated: {},
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(pluginIDs)
	if len(pluginIDs) == 0 && len(permissions) == 0 && len(executionTiers) == 0 && len(stabilities) == 0 {
		return nil, fmt.Errorf("trust scope must contain at least one restriction")
	}
	return &PluginTrustScope{
		PluginIDs: pluginIDs, Permissions: permissions, ExecutionTiers: executionTiers, Stabilities: stabilities,
	}, nil
}

func normalizePluginTrustEnum(values []string, label string, allowed map[string]struct{}) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(strings.ToLower(raw))
		if value == "" {
			continue
		}
		if _, ok := allowed[value]; !ok {
			return nil, fmt.Errorf("trust scope %s %q is not supported", label, value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func clonePluginTrustScope(scope *PluginTrustScope) *PluginTrustScope {
	if scope == nil {
		return nil
	}
	return &PluginTrustScope{
		PluginIDs:      append([]string(nil), scope.PluginIDs...),
		Permissions:    append([]string(nil), scope.Permissions...),
		ExecutionTiers: append([]string(nil), scope.ExecutionTiers...),
		Stabilities:    append([]string(nil), scope.Stabilities...),
	}
}

func equalPluginTrustScopes(left, right *PluginTrustScope) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return equalPluginTrustStringLists(left.PluginIDs, right.PluginIDs) &&
		equalPluginTrustStringLists(left.Permissions, right.Permissions) &&
		equalPluginTrustStringLists(left.ExecutionTiers, right.ExecutionTiers) &&
		equalPluginTrustStringLists(left.Stabilities, right.Stabilities)
}

func equalPluginTrustStringLists(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func pluginTrustScopeContains(outer, inner *PluginTrustScope) bool {
	if outer == nil {
		return true
	}
	if inner == nil {
		return false
	}
	return pluginTrustPluginPatternsContain(outer.PluginIDs, inner.PluginIDs) &&
		pluginTrustValuesContain(outer.Permissions, inner.Permissions) &&
		pluginTrustValuesContain(outer.ExecutionTiers, inner.ExecutionTiers) &&
		pluginTrustValuesContain(outer.Stabilities, inner.Stabilities)
}

func pluginTrustValuesContain(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(outer))
	for _, value := range outer {
		allowed[value] = struct{}{}
	}
	for _, value := range inner {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func pluginTrustPluginPatternsContain(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, candidate := range inner {
		covered := false
		for _, allowed := range outer {
			allowedPrefix := strings.TrimSuffix(allowed, "*")
			candidatePrefix := strings.TrimSuffix(candidate, "*")
			if allowed == candidate || (strings.HasSuffix(allowed, "*") && strings.HasPrefix(candidatePrefix, allowedPrefix)) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func validatePluginTrustKeyScope(key PluginTrustKey, plugin LoadedPlugin) error {
	if key.Scope == nil {
		return nil
	}
	scope := key.Scope
	if len(scope.PluginIDs) > 0 {
		allowed := false
		for _, pattern := range scope.PluginIDs {
			if pattern == plugin.ID || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(plugin.ID, strings.TrimSuffix(pattern, "*"))) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("trusted signer %s is not authorized for plugin %s", key.ID, plugin.ID)
		}
	}
	if len(scope.Stabilities) > 0 && !pluginTrustValueAllowed(scope.Stabilities, plugin.Stability) {
		return fmt.Errorf("trusted signer %s is not authorized for %s stability", key.ID, plugin.Stability)
	}
	tier := pluginPackageExecutionTier(plugin)
	if len(scope.ExecutionTiers) > 0 && !pluginTrustValueAllowed(scope.ExecutionTiers, tier) {
		return fmt.Errorf("trusted signer %s is not authorized for %s execution tier", key.ID, tier)
	}
	if len(scope.Permissions) > 0 && plugin.Control != nil {
		for _, permission := range plugin.Control.Permissions {
			if !pluginTrustValueAllowed(scope.Permissions, permission) {
				return fmt.Errorf("trusted signer %s is not authorized for permission %s", key.ID, permission)
			}
		}
	}
	return nil
}

func pluginTrustValueAllowed(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func (m *pluginPackageManager) verifyArchiveSignature(archiveDigest, signerID, signature string) (PluginTrustKey, bool, error) {
	signerID = strings.TrimSpace(strings.ToLower(signerID))
	signature = strings.TrimSpace(signature)
	if signerID == "" && signature == "" {
		return PluginTrustKey{}, false, nil
	}
	if signerID == "" || signature == "" {
		return PluginTrustKey{}, false, fmt.Errorf("both signer id and signature are required")
	}
	var key PluginTrustKey
	if err := readPluginPackageJSON(filepath.Join(m.stateRoot, "trust", signerID+".json"), &key); err != nil {
		if os.IsNotExist(err) {
			return PluginTrustKey{}, false, fmt.Errorf("plugin signer %s is not trusted", signerID)
		}
		return PluginTrustKey{}, false, err
	}
	if key.Status == "" {
		key.Status = pluginTrustStatusActive
	}
	if err := validatePluginTrustKeyState(key); err != nil {
		return PluginTrustKey{}, false, err
	}
	if key.Status != pluginTrustStatusActive {
		return PluginTrustKey{}, false, fmt.Errorf("plugin signer %s is revoked and not trusted", signerID)
	}
	publicKey, err := decodePluginTrustPublicKey(key.PublicKey)
	if err != nil || pluginTrustKeyID(publicKey) != signerID || key.ID != signerID {
		return PluginTrustKey{}, false, fmt.Errorf("trusted signer %s failed integrity validation", signerID)
	}
	signatureBytes, err := decodePluginPackageSignature(signature)
	if err != nil {
		return PluginTrustKey{}, false, err
	}
	digestBytes, err := hex.DecodeString(archiveDigest)
	if err != nil || len(digestBytes) != sha256.Size {
		return PluginTrustKey{}, false, fmt.Errorf("invalid plugin archive digest")
	}
	message := append([]byte(pluginPackageSignatureDomain), digestBytes...)
	if !ed25519.Verify(publicKey, message, signatureBytes) {
		return PluginTrustKey{}, false, fmt.Errorf("plugin package signature verification failed")
	}
	return key, true, nil
}

func decodePluginTrustPublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	var raw []byte
	var err error
	if raw, err = base64.StdEncoding.DecodeString(value); err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(value); err != nil {
			if raw, err = hex.DecodeString(value); err != nil {
				return nil, fmt.Errorf("public key must be base64 or hexadecimal Ed25519 data")
			}
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func decodePluginPackageSignature(value string) ([]byte, error) {
	var raw []byte
	var err error
	if raw, err = base64.StdEncoding.DecodeString(value); err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(value); err != nil {
			if raw, err = hex.DecodeString(value); err != nil {
				return nil, fmt.Errorf("plugin package signature must be base64 or hexadecimal")
			}
		}
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("Ed25519 signature must be %d bytes", ed25519.SignatureSize)
	}
	return raw, nil
}

func pluginTrustKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:16])
}

func newPluginPackageID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func writePluginPackageJSONAtomic(path string, value any, replace bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tempID, err := newPluginPackageID()
	if err != nil {
		return err
	}
	tempPath := path + ".tmp-" + tempID
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- tempPath is manager-owned and random.
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tempPath)
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("path already exists")
		} else if !os.IsNotExist(err) {
			_ = os.Remove(tempPath)
			return err
		}
	}
	if err := os.Rename(tempPath, path); err != nil {
		if replace {
			if removeErr := os.Remove(path); removeErr == nil || os.IsNotExist(removeErr) {
				err = os.Rename(tempPath, path)
			}
		}
		if err != nil {
			_ = os.Remove(tempPath)
			return err
		}
	}
	return os.Chmod(path, 0o600)
}

func readPluginPackageJSON(path string, target any) error {
	data, _, err := readBoundedRegularFileAtPath(path, 1<<20, false)
	if err != nil {
		if os.IsNotExist(err) {
			return err
		}
		return fmt.Errorf("metadata path is not a bounded regular file: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("metadata contains trailing JSON values")
		}
		return fmt.Errorf("metadata contains trailing content: %w", err)
	}
	return nil
}
