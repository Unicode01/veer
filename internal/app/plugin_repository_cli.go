package app

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	pluginRepositoryPublisherFormatVersion = 1
	pluginRepositoryPublisherStateFile     = "repository.json"
	pluginRepositoryPublisherJournalFile   = "publish.json"
	pluginRepositoryPublisherMaxStateBytes = 16 << 20
	pluginRepositoryPublisherRootDays      = 365
	pluginRepositoryPublisherTargetsDays   = 30
	pluginRepositoryPublisherSnapshotDays  = 7
	pluginRepositoryPublisherTimestampDays = 1
)

type pluginRepositoryPublisherState struct {
	FormatVersion   int                               `json:"format_version"`
	RootVersion     int64                             `json:"root_version"`
	MetadataVersion int64                             `json:"metadata_version"`
	KeyVersions     map[string]int64                  `json:"key_versions"`
	CreatedAt       string                            `json:"created_at"`
	UpdatedAt       string                            `json:"updated_at"`
	Targets         []pluginRepositoryPublisherTarget `json:"targets"`
}

type pluginRepositoryPublisherTarget struct {
	PluginID         string               `json:"plugin_id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Version          string               `json:"version"`
	Channel          string               `json:"channel"`
	Stability        string               `json:"stability"`
	Compatibility    *PluginCompatibility `json:"compatibility,omitempty"`
	Dependencies     []PluginDependency   `json:"dependencies,omitempty"`
	Conflicts        []PluginConflict     `json:"conflicts,omitempty"`
	ArchivePath      string               `json:"archive_path"`
	ArchiveSHA256    string               `json:"archive_sha256"`
	Length           int64                `json:"length"`
	Revoked          bool                 `json:"revoked,omitempty"`
	RevocationReason string               `json:"revocation_reason,omitempty"`
}

type pluginRepositoryPublisherJournal struct {
	FormatVersion int                            `json:"format_version"`
	ID            string                         `json:"id"`
	Phase         string                         `json:"phase"`
	NextDir       string                         `json:"next_dir"`
	BackupDir     string                         `json:"backup_dir"`
	State         pluginRepositoryPublisherState `json:"state"`
}

type pluginRepositoryPublisherRotationJournal struct {
	FormatVersion  int                            `json:"format_version"`
	Role           string                         `json:"role"`
	NewKeyVersion  int64                          `json:"new_key_version"`
	NewRootVersion int64                          `json:"new_root_version"`
	PrivateKeyPEM  []byte                         `json:"private_key_pem"`
	Root           json.RawMessage                `json:"root"`
	State          pluginRepositoryPublisherState `json:"state"`
}

func runPluginRepositoryCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		writePluginRepositoryCLIUsage(stderr)
		return fmt.Errorf("plugin repository subcommand is required")
	}
	switch args[0] {
	case "init":
		return runPluginRepositoryInitCLI(args[1:], stdout, stderr)
	case "add":
		return runPluginRepositoryAddCLI(args[1:], stdout, stderr)
	case "revoke":
		return runPluginRepositoryRevokeCLI(args[1:], stdout, stderr)
	case "publish":
		return runPluginRepositoryPublishCLI(args[1:], stdout, stderr)
	case "rotate-key":
		return runPluginRepositoryRotateKeyCLI(args[1:], stdout, stderr)
	case "status":
		return runPluginRepositoryStatusCLI(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		writePluginRepositoryCLIUsage(stdout)
		return nil
	default:
		writePluginRepositoryCLIUsage(stderr)
		return fmt.Errorf("unknown plugin repository subcommand %q", args[0])
	}
}

func writePluginRepositoryCLIUsage(w io.Writer) {
	fmt.Fprintln(w, "Veer TUF plugin repository tools:")
	fmt.Fprintln(w, "  veer plugin repository init --directory DIR")
	fmt.Fprintln(w, "  veer plugin repository add --directory DIR --archive FILE --channel stable|preview")
	fmt.Fprintln(w, "  veer plugin repository revoke --directory DIR --plugin ID --version VERSION --channel CHANNEL --reason TEXT")
	fmt.Fprintln(w, "  veer plugin repository publish --directory DIR")
	fmt.Fprintln(w, "  veer plugin repository rotate-key --directory DIR --role root|targets|snapshot|timestamp")
	fmt.Fprintln(w, "  veer plugin repository status --directory DIR")
}

func runPluginRepositoryInitCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "new private repository workspace")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" {
		return fmt.Errorf("plugin repository init requires --directory and no positional arguments")
	}
	workspace, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if err := os.Mkdir(workspace, 0o700); err != nil {
		return fmt.Errorf("create repository workspace: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(workspace)
		}
	}()
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(workspace)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	for _, directory := range []string{"keys", "roots", "packages"} {
		if err := os.Mkdir(filepath.Join(workspace, directory), 0o700); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	root := tufmetadata.Root(now.Add(pluginRepositoryPublisherRootDays * 24 * time.Hour))
	keyVersions := make(map[string]int64, 4)
	privateKeys := make(map[string]ed25519.PrivateKey, 4)
	for _, role := range pluginRepositoryTopLevelRoles() {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		key, err := tufmetadata.KeyFromPublicKey(publicKey)
		if err != nil {
			return err
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			return err
		}
		keyVersions[role] = 1
		privateKeys[role] = privateKey
		if err := writePluginRepositoryPrivateKey(pluginRepositoryPublisherKeyPath(workspace, role, 1), privateKey); err != nil {
			return err
		}
	}
	if err := signPluginRepositoryMetadata(root, privateKeys[tufmetadata.ROOT]); err != nil {
		return err
	}
	if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
		return fmt.Errorf("verify initial root metadata: %w", err)
	}
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		return err
	}
	if err := writePluginPackageFileAtomic(pluginRepositoryPublisherRootPath(workspace, 1), rootBytes, false, 0o600); err != nil {
		return err
	}
	state := pluginRepositoryPublisherState{
		FormatVersion: pluginRepositoryPublisherFormatVersion, RootVersion: 1, KeyVersions: keyVersions,
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		Targets: []pluginRepositoryPublisherTarget{},
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), state, false); err != nil {
		return err
	}
	result, err := publishPluginRepositoryWorkspace(workspace)
	if err != nil {
		return err
	}
	cleanup = false
	return writePluginPackageCLIJSON(stdout, result)
}

func runPluginRepositoryAddCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "private repository workspace")
	archivePath := flags.String("archive", "", "validated Veer plugin package")
	channelValue := flags.String("channel", pluginRepositoryChannelStable, "stable or preview")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*archivePath) == "" {
		return fmt.Errorf("plugin repository add requires --directory, --archive, and no positional arguments")
	}
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(*directory)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	workspace, state, err := loadPluginRepositoryPublisherWorkspace(*directory)
	if err != nil {
		return err
	}
	channel, err := normalizePluginRepositoryChannel(*channelValue)
	if err != nil {
		return err
	}
	archive, plugin, data, err := inspectPluginRepositoryPublisherArchive(*archivePath)
	if err != nil {
		return err
	}
	if err := validatePluginRepositoryCandidateStability(channel, plugin.Stability); err != nil {
		return err
	}
	relativeArchive := filepath.ToSlash(filepath.Join("packages", channel, plugin.ID, plugin.Version, "package.tar.gz"))
	target := pluginRepositoryPublisherTarget{
		PluginID: plugin.ID, Name: plugin.Name, Description: plugin.Description,
		Version: plugin.Version, Channel: channel, Stability: plugin.Stability,
		Compatibility: clonePluginCompatibility(plugin.Compatibility),
		Dependencies:  append([]PluginDependency(nil), plugin.Dependencies...),
		Conflicts:     append([]PluginConflict(nil), plugin.Conflicts...),
		ArchivePath:   relativeArchive, ArchiveSHA256: archive.ArchiveSHA256, Length: archive.Bytes,
	}
	for _, existing := range state.Targets {
		if existing.PluginID != target.PluginID || existing.Version != target.Version || existing.Channel != target.Channel {
			continue
		}
		if !reflect.DeepEqual(existing, target) {
			return fmt.Errorf("repository already contains immutable target %s %s with different metadata", target.PluginID, target.Version)
		}
		return writePluginPackageCLIJSON(stdout, map[string]any{"status": "unchanged", "plugin_id": target.PluginID, "version": target.Version, "channel": target.Channel})
	}
	destination := filepath.Join(workspace, filepath.FromSlash(relativeArchive))
	if err := writePluginPackageFileAtomic(destination, data, false, 0o600); err != nil {
		return fmt.Errorf("store repository package: %w", err)
	}
	state.Targets = append(state.Targets, target)
	sortPluginRepositoryPublisherTargets(state.Targets)
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validatePluginRepositoryPublisherState(workspace, state); err != nil {
		_ = os.Remove(destination)
		return err
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), state, true); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"status": "added", "plugin_id": target.PluginID, "version": target.Version,
		"channel": target.Channel, "archive_sha256": target.ArchiveSHA256,
	})
}

func runPluginRepositoryRevokeCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "private repository workspace")
	pluginID := flags.String("plugin", "", "plugin id")
	version := flags.String("version", "", "strict plugin version")
	channelValue := flags.String("channel", pluginRepositoryChannelStable, "stable or preview")
	reason := flags.String("reason", "", "security or compatibility revocation reason")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*pluginID) == "" || strings.TrimSpace(*version) == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("plugin repository revoke requires --directory, --plugin, --version, --reason, and no positional arguments")
	}
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(*directory)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	workspace, state, err := loadPluginRepositoryPublisherWorkspace(*directory)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(strings.ToLower(*pluginID))
	normalizedVersion, err := normalizePluginSemanticVersion(*version)
	if err != nil || normalizedVersion != strings.TrimSpace(*version) {
		return fmt.Errorf("plugin version must be strict SemVer")
	}
	channel, err := normalizePluginRepositoryChannel(*channelValue)
	if err != nil {
		return err
	}
	revocationReason := strings.TrimSpace(*reason)
	if len(revocationReason) > 1024 || strings.ContainsAny(revocationReason, "\x00\r\n") {
		return fmt.Errorf("revocation reason is invalid")
	}
	found := false
	for i := range state.Targets {
		target := &state.Targets[i]
		if target.PluginID != id || target.Version != normalizedVersion || target.Channel != channel {
			continue
		}
		found = true
		if target.Revoked {
			if target.RevocationReason != revocationReason {
				return fmt.Errorf("target is already revoked with a different immutable reason")
			}
			return writePluginPackageCLIJSON(stdout, map[string]any{"status": "unchanged", "plugin_id": id, "version": normalizedVersion, "channel": channel})
		}
		target.Revoked = true
		target.RevocationReason = revocationReason
		break
	}
	if !found {
		return fmt.Errorf("repository target %s %s on %s was not found", id, normalizedVersion, channel)
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validatePluginRepositoryPublisherState(workspace, state); err != nil {
		return err
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), state, true); err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"status": "revoked", "plugin_id": id, "version": normalizedVersion, "channel": channel, "reason": revocationReason,
	})
}

func runPluginRepositoryPublishCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository publish", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "private repository workspace")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" {
		return fmt.Errorf("plugin repository publish requires --directory and no positional arguments")
	}
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(*directory)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	workspace, _, err := loadPluginRepositoryPublisherWorkspace(*directory)
	if err != nil {
		return err
	}
	result, err := publishPluginRepositoryWorkspace(workspace)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, result)
}

func runPluginRepositoryStatusCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "private repository workspace")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" {
		return fmt.Errorf("plugin repository status requires --directory and no positional arguments")
	}
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(*directory)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	workspace, state, err := loadPluginRepositoryPublisherWorkspace(*directory)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{
		"workspace": workspace, "public_directory": filepath.Join(workspace, "public"),
		"initial_root": filepath.Join(workspace, "public", "metadata", "root.json"),
		"root_version": state.RootVersion, "metadata_version": state.MetadataVersion,
		"targets": state.Targets,
	})
}

func runPluginRepositoryRotateKeyCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin repository rotate-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "private repository workspace")
	roleValue := flags.String("role", "", "root, targets, snapshot, or timestamp")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" || strings.TrimSpace(*roleValue) == "" {
		return fmt.Errorf("plugin repository rotate-key requires --directory, --role, and no positional arguments")
	}
	role := strings.TrimSpace(strings.ToLower(*roleValue))
	if !pluginRepositoryTopLevelRole(role) {
		return fmt.Errorf("repository role must be root, targets, snapshot, or timestamp")
	}
	_, workspaceLock, err := acquirePluginRepositoryPublisherLock(*directory)
	if err != nil {
		return err
	}
	defer workspaceLock.Close()
	workspace, state, err := loadPluginRepositoryPublisherWorkspace(*directory)
	if err != nil {
		return err
	}
	oldRoot, oldRootBytes, err := loadPluginRepositoryPublisherRoot(workspace, state.RootVersion)
	if err != nil {
		return err
	}
	if err := oldRoot.VerifyDelegate(tufmetadata.ROOT, oldRoot); err != nil {
		return fmt.Errorf("current root self-verification failed: %w", err)
	}
	oldRoleKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, role)
	if err != nil {
		return err
	}
	oldRoleMetadataKey, err := tufmetadata.KeyFromPublicKey(oldRoleKey.Public())
	if err != nil {
		return err
	}
	oldRoleKeyID, err := oldRoleMetadataKey.ID()
	if err != nil {
		return err
	}
	if !pluginRepositoryRoleContainsKey(oldRoot.Signed.Roles[role], oldRoleKeyID) {
		return fmt.Errorf("current %s private key does not match root metadata", role)
	}
	publicKey, newPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	newMetadataKey, err := tufmetadata.KeyFromPublicKey(publicKey)
	if err != nil {
		return err
	}
	newRoot, err := tufmetadata.Root().FromBytes(oldRootBytes)
	if err != nil {
		return err
	}
	newRoot.Signed.Version = state.RootVersion + 1
	newRoot.Signed.Expires = time.Now().UTC().Add(pluginRepositoryPublisherRootDays * 24 * time.Hour)
	newRoot.ClearSignatures()
	if err := newRoot.Signed.RevokeKey(oldRoleKeyID, role); err != nil {
		return err
	}
	if err := newRoot.Signed.AddKey(newMetadataKey, role); err != nil {
		return err
	}
	if role == tufmetadata.ROOT {
		if err := signPluginRepositoryMetadata(newRoot, oldRoleKey); err != nil {
			return err
		}
		if err := signPluginRepositoryMetadata(newRoot, newPrivateKey); err != nil {
			return err
		}
	} else {
		rootKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, tufmetadata.ROOT)
		if err != nil {
			return err
		}
		if err := signPluginRepositoryMetadata(newRoot, rootKey); err != nil {
			return err
		}
	}
	if err := oldRoot.VerifyDelegate(tufmetadata.ROOT, newRoot); err != nil {
		return fmt.Errorf("new root is not authorized by the current root: %w", err)
	}
	if err := newRoot.VerifyDelegate(tufmetadata.ROOT, newRoot); err != nil {
		return fmt.Errorf("new root self-verification failed: %w", err)
	}
	rootBytes, err := newRoot.ToBytes(false)
	if err != nil {
		return err
	}
	privatePEM, err := marshalPluginRepositoryPrivateKey(newPrivateKey)
	if err != nil {
		return err
	}
	state.RootVersion++
	state.KeyVersions[role]++
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	journal := pluginRepositoryPublisherRotationJournal{
		FormatVersion: pluginRepositoryPublisherFormatVersion, Role: role,
		NewKeyVersion: state.KeyVersions[role], NewRootVersion: state.RootVersion,
		PrivateKeyPEM: privatePEM, Root: append(json.RawMessage(nil), rootBytes...), State: state,
	}
	rotationPath := filepath.Join(workspace, "rotation.json")
	if err := writePluginPackageJSONAtomic(rotationPath, journal, false); err != nil {
		return err
	}
	if err := recoverPluginRepositoryPublisherRotation(workspace); err != nil {
		return err
	}
	result, err := publishPluginRepositoryWorkspace(workspace)
	if err != nil {
		return fmt.Errorf("key rotation was committed but publishing the new root failed: %w", err)
	}
	result["rotated_role"] = role
	result["root_version"] = state.RootVersion
	return writePluginPackageCLIJSON(stdout, result)
}

func publishPluginRepositoryWorkspace(workspace string) (map[string]any, error) {
	workspace, state, err := loadPluginRepositoryPublisherWorkspace(workspace)
	if err != nil {
		return nil, err
	}
	metadataVersion := state.MetadataVersion + 1
	if metadataVersion < 1 {
		return nil, fmt.Errorf("repository metadata version overflow")
	}
	id, err := newPluginPackageID()
	if err != nil {
		return nil, err
	}
	nextName := ".public-next-" + id
	backupName := ".public-backup-" + id
	nextDir := filepath.Join(workspace, nextName)
	if err := os.Mkdir(nextDir, 0o700); err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = removePluginPackageManagedPath(workspace, nextDir)
		}
	}()
	rootHash, err := buildPluginRepositoryPublicTree(workspace, nextDir, state, metadataVersion)
	if err != nil {
		return nil, err
	}
	candidateState := state
	candidateState.MetadataVersion = metadataVersion
	candidateState.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	journal := pluginRepositoryPublisherJournal{
		FormatVersion: pluginRepositoryPublisherFormatVersion, ID: id, Phase: "prepared",
		NextDir: nextName, BackupDir: backupName, State: candidateState,
	}
	journalPath := filepath.Join(workspace, pluginRepositoryPublisherJournalFile)
	if err := writePluginPackageJSONAtomic(journalPath, journal, false); err != nil {
		return nil, err
	}
	cleanup = false
	if err := completePluginRepositoryPublisherJournal(workspace, journal); err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "published", "public_directory": filepath.Join(workspace, "public"),
		"initial_root": filepath.Join(workspace, "public", "metadata", "root.json"),
		"root_sha256":  rootHash, "root_version": state.RootVersion,
		"metadata_version": metadataVersion, "target_count": len(state.Targets),
	}, nil
}

func buildPluginRepositoryPublicTree(workspace, publicRoot string, state pluginRepositoryPublisherState, metadataVersion int64) (string, error) {
	root, currentRootBytes, err := loadPluginRepositoryPublisherRoot(workspace, state.RootVersion)
	if err != nil {
		return "", err
	}
	if root.Signed.IsExpired(time.Now()) {
		return "", fmt.Errorf("repository root metadata is expired; rotate a top-level key to renew it")
	}
	targetsKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, tufmetadata.TARGETS)
	if err != nil {
		return "", err
	}
	snapshotKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, tufmetadata.SNAPSHOT)
	if err != nil {
		return "", err
	}
	timestampKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, tufmetadata.TIMESTAMP)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	targets := tufmetadata.Targets(now.Add(pluginRepositoryPublisherTargetsDays * 24 * time.Hour))
	targets.Signed.Version = metadataVersion
	for _, target := range state.Targets {
		archivePath := filepath.Join(workspace, filepath.FromSlash(target.ArchivePath))
		_, data, info, err := readPluginCLIRegularFile(archivePath, pluginPackageMaxArchiveBytes)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		if info.Size() != target.Length || hex.EncodeToString(digest[:]) != target.ArchiveSHA256 {
			return "", fmt.Errorf("repository package %s %s failed state integrity validation", target.PluginID, target.Version)
		}
		targetPath := pluginRepositoryPublisherTargetPath(target)
		metadata, err := tufmetadata.TargetFile().FromBytes(targetPath, data, "sha256")
		if err != nil {
			return "", err
		}
		custom, err := json.Marshal(target.pluginRepositoryMetadata())
		if err != nil {
			return "", err
		}
		customRaw := json.RawMessage(custom)
		metadata.Custom = &customRaw
		targets.Signed.Targets[targetPath] = metadata
		directory, base := filepath.Split(filepath.FromSlash(targetPath))
		publicTarget := filepath.Join(publicRoot, "targets", directory, target.ArchiveSHA256+"."+base)
		if err := writePluginPackageFileAtomic(publicTarget, data, false, 0o644); err != nil {
			return "", err
		}
	}
	if err := signPluginRepositoryMetadata(targets, targetsKey); err != nil {
		return "", err
	}
	if err := root.VerifyDelegate(tufmetadata.TARGETS, targets); err != nil {
		return "", fmt.Errorf("verify targets metadata: %w", err)
	}
	targetsBytes, err := targets.ToBytes(false)
	if err != nil {
		return "", err
	}
	snapshot := tufmetadata.Snapshot(now.Add(pluginRepositoryPublisherSnapshotDays * 24 * time.Hour))
	snapshot.Signed.Version = metadataVersion
	snapshot.Signed.Meta["targets.json"] = pluginRepositoryPublisherMetaFile(metadataVersion, targetsBytes)
	if err := signPluginRepositoryMetadata(snapshot, snapshotKey); err != nil {
		return "", err
	}
	if err := root.VerifyDelegate(tufmetadata.SNAPSHOT, snapshot); err != nil {
		return "", fmt.Errorf("verify snapshot metadata: %w", err)
	}
	snapshotBytes, err := snapshot.ToBytes(false)
	if err != nil {
		return "", err
	}
	timestamp := tufmetadata.Timestamp(now.Add(pluginRepositoryPublisherTimestampDays * 24 * time.Hour))
	timestamp.Signed.Version = metadataVersion
	timestamp.Signed.Meta["snapshot.json"] = pluginRepositoryPublisherMetaFile(metadataVersion, snapshotBytes)
	if err := signPluginRepositoryMetadata(timestamp, timestampKey); err != nil {
		return "", err
	}
	if err := root.VerifyDelegate(tufmetadata.TIMESTAMP, timestamp); err != nil {
		return "", fmt.Errorf("verify timestamp metadata: %w", err)
	}
	timestampBytes, err := timestamp.ToBytes(false)
	if err != nil {
		return "", err
	}
	metadataDir := filepath.Join(publicRoot, "metadata")
	for version := int64(1); version <= state.RootVersion; version++ {
		_, rootBytes, err := loadPluginRepositoryPublisherRoot(workspace, version)
		if err != nil {
			return "", err
		}
		if err := writePluginPackageFileAtomic(filepath.Join(metadataDir, fmt.Sprintf("%d.root.json", version)), rootBytes, false, 0o644); err != nil {
			return "", err
		}
	}
	for path, data := range map[string][]byte{
		filepath.Join(metadataDir, "root.json"):                                      currentRootBytes,
		filepath.Join(metadataDir, fmt.Sprintf("%d.targets.json", metadataVersion)):  targetsBytes,
		filepath.Join(metadataDir, fmt.Sprintf("%d.snapshot.json", metadataVersion)): snapshotBytes,
		filepath.Join(metadataDir, "timestamp.json"):                                 timestampBytes,
	} {
		if err := writePluginPackageFileAtomic(path, data, false, 0o644); err != nil {
			return "", err
		}
	}
	rootDigest := sha256.Sum256(currentRootBytes)
	return hex.EncodeToString(rootDigest[:]), nil
}

func pluginRepositoryPublisherMetaFile(version int64, data []byte) *tufmetadata.MetaFiles {
	digest := sha256.Sum256(data)
	return &tufmetadata.MetaFiles{
		Version: version, Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": tufmetadata.HexBytes(append([]byte(nil), digest[:]...))},
	}
}

func loadPluginRepositoryPublisherWorkspace(directory string) (string, pluginRepositoryPublisherState, error) {
	workspace, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	info, err := os.Lstat(workspace)
	if err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", pluginRepositoryPublisherState{}, fmt.Errorf("repository workspace must be a regular directory")
	}
	if err := recoverPluginRepositoryPublisherRotation(workspace); err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	if err := recoverPluginRepositoryPublisherPublish(workspace); err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	var state pluginRepositoryPublisherState
	if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &state); err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	if err := validatePluginRepositoryPublisherState(workspace, state); err != nil {
		return "", pluginRepositoryPublisherState{}, err
	}
	return workspace, state, nil
}

func validatePluginRepositoryPublisherState(workspace string, state pluginRepositoryPublisherState) error {
	if state.FormatVersion != pluginRepositoryPublisherFormatVersion || state.RootVersion < 1 || state.MetadataVersion < 0 {
		return fmt.Errorf("repository publisher state version is invalid")
	}
	createdAt, createdErr := time.Parse(time.RFC3339Nano, state.CreatedAt)
	updatedAt, updatedErr := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if createdErr != nil || updatedErr != nil || createdAt.IsZero() || updatedAt.Before(createdAt) {
		return fmt.Errorf("repository publisher timestamps are invalid")
	}
	if len(state.KeyVersions) != 4 {
		return fmt.Errorf("repository publisher key state is incomplete")
	}
	for _, role := range pluginRepositoryTopLevelRoles() {
		if state.KeyVersions[role] < 1 {
			return fmt.Errorf("repository publisher %s key version is invalid", role)
		}
	}
	if len(state.Targets) > pluginRepositoryMaxTargets {
		return fmt.Errorf("repository publisher target count exceeds %d", pluginRepositoryMaxTargets)
	}
	seenTargets := make(map[string]struct{}, len(state.Targets))
	for _, target := range state.Targets {
		targetPath := pluginRepositoryPublisherTargetPath(target)
		catalogTarget := PluginRepositoryTarget{
			Target: targetPath, PluginID: target.PluginID, Name: target.Name, Description: target.Description,
			Version: target.Version, Channel: target.Channel, Stability: target.Stability,
			Compatibility: clonePluginCompatibility(target.Compatibility),
			Dependencies:  append([]PluginDependency(nil), target.Dependencies...),
			Conflicts:     append([]PluginConflict(nil), target.Conflicts...),
			Length:        target.Length, SHA256: target.ArchiveSHA256,
			Revoked: target.Revoked, RevocationReason: target.RevocationReason,
		}
		if err := validatePluginRepositoryCatalogTarget(catalogTarget); err != nil {
			return fmt.Errorf("repository publisher target %s: %w", target.PluginID, err)
		}
		expectedArchive := filepath.ToSlash(filepath.Join("packages", target.Channel, target.PluginID, target.Version, "package.tar.gz"))
		if target.ArchivePath != expectedArchive {
			return fmt.Errorf("repository publisher target %s archive path is invalid", target.PluginID)
		}
		key := target.PluginID + "\x00" + target.Version + "\x00" + target.Channel
		if _, duplicate := seenTargets[key]; duplicate {
			return fmt.Errorf("repository publisher contains duplicate target %s %s", target.PluginID, target.Version)
		}
		seenTargets[key] = struct{}{}
		archivePath := filepath.Join(workspace, filepath.FromSlash(target.ArchivePath))
		info, err := os.Lstat(archivePath)
		if err != nil {
			return fmt.Errorf("repository publisher package %s: %w", target.PluginID, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != target.Length {
			return fmt.Errorf("repository publisher package %s is not a bounded regular file", target.PluginID)
		}
	}
	root, _, err := loadPluginRepositoryPublisherRoot(workspace, state.RootVersion)
	if err != nil {
		return err
	}
	if root.Signed.Version != state.RootVersion {
		return fmt.Errorf("repository root version does not match publisher state")
	}
	if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
		return fmt.Errorf("repository root self-verification failed: %w", err)
	}
	for _, role := range pluginRepositoryTopLevelRoles() {
		privateKey, err := loadPluginRepositoryPublisherRoleKey(workspace, state, role)
		if err != nil {
			return err
		}
		metadataKey, err := tufmetadata.KeyFromPublicKey(privateKey.Public())
		if err != nil {
			return err
		}
		keyID, err := metadataKey.ID()
		if err != nil || !pluginRepositoryRoleContainsKey(root.Signed.Roles[role], keyID) {
			return fmt.Errorf("repository %s private key does not match current root metadata", role)
		}
	}
	return nil
}

func recoverPluginRepositoryPublisherPublish(workspace string) error {
	journalPath := filepath.Join(workspace, pluginRepositoryPublisherJournalFile)
	var journal pluginRepositoryPublisherJournal
	if err := readPluginRepositoryJSON(journalPath, pluginRepositoryPublisherMaxStateBytes, &journal); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read repository publish journal: %w", err)
	}
	if err := validatePluginRepositoryPublisherJournal(journal); err != nil {
		return err
	}
	return completePluginRepositoryPublisherJournal(workspace, journal)
}

func validatePluginRepositoryPublisherJournal(journal pluginRepositoryPublisherJournal) error {
	if journal.FormatVersion != pluginRepositoryPublisherFormatVersion || validatePluginPackageID(journal.ID) != nil ||
		journal.NextDir != ".public-next-"+journal.ID || journal.BackupDir != ".public-backup-"+journal.ID {
		return fmt.Errorf("repository publish journal identity is invalid")
	}
	if journal.Phase != "prepared" && journal.Phase != "old_moved" && journal.Phase != "new_moved" {
		return fmt.Errorf("repository publish journal phase is invalid")
	}
	if journal.State.MetadataVersion < 1 {
		return fmt.Errorf("repository publish journal state is invalid")
	}
	return nil
}

func completePluginRepositoryPublisherJournal(workspace string, journal pluginRepositoryPublisherJournal) error {
	if err := validatePluginRepositoryPublisherJournal(journal); err != nil {
		return err
	}
	currentState, stateCommitted, err := validatePluginRepositoryPublisherJournalTransition(workspace, journal.State)
	if err != nil {
		return err
	}
	publicDir := filepath.Join(workspace, "public")
	nextDir := filepath.Join(workspace, journal.NextDir)
	backupDir := filepath.Join(workspace, journal.BackupDir)
	publicExists, err := pluginRepositoryPublisherDirectoryExists(publicDir)
	if err != nil {
		return err
	}
	nextExists, err := pluginRepositoryPublisherDirectoryExists(nextDir)
	if err != nil {
		return err
	}
	backupExists, err := pluginRepositoryPublisherDirectoryExists(backupDir)
	if err != nil {
		return err
	}
	journalPath := filepath.Join(workspace, pluginRepositoryPublisherJournalFile)
	if publicExists && nextExists {
		if journal.Phase != "prepared" || backupExists {
			return fmt.Errorf("repository publish recovery found both active and candidate public trees")
		}
	}
	if !backupExists && publicExists && !nextExists {
		if !stateCommitted && currentState.MetadataVersion != 0 {
			return fmt.Errorf("repository publish candidate and backup disappeared before state commit")
		}
		journal.Phase = "new_moved"
	}
	if publicExists && backupExists && !nextExists {
		journal.Phase = "new_moved"
	}
	if !publicExists && nextExists {
		if !backupExists {
			if currentExists, err := pluginRepositoryPublisherDirectoryExists(filepath.Join(workspace, "public")); err != nil || currentExists {
				return fmt.Errorf("repository publish recovery state is inconsistent")
			}
		}
		journal.Phase = "old_moved"
	}
	if journal.Phase == "prepared" {
		if publicExists {
			if err := os.Rename(publicDir, backupDir); err != nil {
				return fmt.Errorf("move previous public repository: %w", err)
			}
			backupExists = true
			publicExists = false
		}
		journal.Phase = "old_moved"
		if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
			return err
		}
	}
	if journal.Phase == "old_moved" {
		publicExists, _ = pluginRepositoryPublisherDirectoryExists(publicDir)
		nextExists, _ = pluginRepositoryPublisherDirectoryExists(nextDir)
		if !publicExists {
			if !nextExists {
				return fmt.Errorf("repository publish candidate disappeared during recovery")
			}
			if err := os.Rename(nextDir, publicDir); err != nil {
				return fmt.Errorf("activate public repository: %w", err)
			}
		}
		journal.Phase = "new_moved"
		if err := writePluginPackageJSONAtomic(journalPath, journal, true); err != nil {
			return err
		}
	}
	publicExists, err = pluginRepositoryPublisherDirectoryExists(publicDir)
	if err != nil || !publicExists {
		if err == nil {
			err = fmt.Errorf("active public repository is missing")
		}
		return err
	}
	if err := validatePluginRepositoryPublisherPublicTree(publicDir, journal.State); err != nil {
		return fmt.Errorf("validate active public repository: %w", err)
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), journal.State, true); err != nil {
		return fmt.Errorf("commit repository publisher state: %w", err)
	}
	if backupExists {
		if err := removePluginPackageManagedPath(workspace, backupDir); err != nil {
			return err
		}
	}
	if nextExists, _ := pluginRepositoryPublisherDirectoryExists(nextDir); nextExists {
		if err := removePluginPackageManagedPath(workspace, nextDir); err != nil {
			return err
		}
	}
	return os.Remove(journalPath)
}

func validatePluginRepositoryPublisherJournalTransition(workspace string, candidate pluginRepositoryPublisherState) (pluginRepositoryPublisherState, bool, error) {
	var current pluginRepositoryPublisherState
	if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &current); err != nil {
		return pluginRepositoryPublisherState{}, false, fmt.Errorf("read repository state before publish recovery: %w", err)
	}
	if err := validatePluginRepositoryPublisherState(workspace, candidate); err != nil {
		return pluginRepositoryPublisherState{}, false, fmt.Errorf("validate repository publish candidate state: %w", err)
	}
	if reflect.DeepEqual(current, candidate) {
		return current, true, nil
	}
	if candidate.MetadataVersion != current.MetadataVersion+1 {
		return pluginRepositoryPublisherState{}, false, fmt.Errorf("repository publish journal metadata version is not consecutive")
	}
	expected := current
	expected.MetadataVersion = candidate.MetadataVersion
	expected.UpdatedAt = candidate.UpdatedAt
	if !reflect.DeepEqual(expected, candidate) {
		return pluginRepositoryPublisherState{}, false, fmt.Errorf("repository publish journal changes state outside the metadata version")
	}
	return current, false, nil
}

func validatePluginRepositoryPublisherPublicTree(publicDir string, state pluginRepositoryPublisherState) error {
	if state.MetadataVersion < 1 {
		return fmt.Errorf("published metadata version is invalid")
	}
	rootPath := filepath.Join(publicDir, "metadata", "root.json")
	_, rootBytes, _, err := readPluginCLIRegularFile(rootPath, pluginRepositoryPublisherMaxStateBytes)
	if err != nil {
		return err
	}
	_, versionedRootBytes, _, err := readPluginCLIRegularFile(
		filepath.Join(publicDir, "metadata", fmt.Sprintf("%d.root.json", state.RootVersion)),
		pluginRepositoryPublisherMaxStateBytes,
	)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(rootBytes, versionedRootBytes) {
		return fmt.Errorf("current and versioned root metadata differ")
	}
	root, err := tufmetadata.Root().FromBytes(rootBytes)
	if err != nil || root.Signed.Version != state.RootVersion {
		return fmt.Errorf("published root metadata is invalid")
	}
	if err := root.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
		return fmt.Errorf("verify published root metadata: %w", err)
	}

	_, targetsBytes, _, err := readPluginCLIRegularFile(
		filepath.Join(publicDir, "metadata", fmt.Sprintf("%d.targets.json", state.MetadataVersion)),
		pluginRepositoryPublisherMaxStateBytes,
	)
	if err != nil {
		return err
	}
	targets, err := tufmetadata.Targets().FromBytes(targetsBytes)
	if err != nil || targets.Signed.Version != state.MetadataVersion || len(targets.Signed.Targets) != len(state.Targets) {
		return fmt.Errorf("published targets metadata is invalid")
	}
	if err := root.VerifyDelegate(tufmetadata.TARGETS, targets); err != nil {
		return fmt.Errorf("verify published targets metadata: %w", err)
	}
	for _, target := range state.Targets {
		targetPath := pluginRepositoryPublisherTargetPath(target)
		metadata := targets.Signed.Targets[targetPath]
		if metadata == nil || metadata.Length != target.Length || hex.EncodeToString(metadata.Hashes["sha256"]) != target.ArchiveSHA256 {
			return fmt.Errorf("published target metadata for %s %s is invalid", target.PluginID, target.Version)
		}
		directory, base := filepath.Split(filepath.FromSlash(targetPath))
		publicTarget := filepath.Join(publicDir, "targets", directory, target.ArchiveSHA256+"."+base)
		_, data, info, err := readPluginCLIRegularFile(publicTarget, pluginPackageMaxArchiveBytes)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if info.Size() != target.Length || hex.EncodeToString(digest[:]) != target.ArchiveSHA256 {
			return fmt.Errorf("published target file for %s %s failed integrity validation", target.PluginID, target.Version)
		}
	}

	_, snapshotBytes, _, err := readPluginCLIRegularFile(
		filepath.Join(publicDir, "metadata", fmt.Sprintf("%d.snapshot.json", state.MetadataVersion)),
		pluginRepositoryPublisherMaxStateBytes,
	)
	if err != nil {
		return err
	}
	snapshot, err := tufmetadata.Snapshot().FromBytes(snapshotBytes)
	if err != nil || snapshot.Signed.Version != state.MetadataVersion {
		return fmt.Errorf("published snapshot metadata is invalid")
	}
	if err := root.VerifyDelegate(tufmetadata.SNAPSHOT, snapshot); err != nil {
		return fmt.Errorf("verify published snapshot metadata: %w", err)
	}
	targetsMeta := snapshot.Signed.Meta["targets.json"]
	if targetsMeta == nil || targetsMeta.Version != state.MetadataVersion || targetsMeta.VerifyLengthHashes(targetsBytes) != nil {
		return fmt.Errorf("published snapshot targets reference is invalid")
	}

	_, timestampBytes, _, err := readPluginCLIRegularFile(
		filepath.Join(publicDir, "metadata", "timestamp.json"),
		pluginRepositoryPublisherMaxStateBytes,
	)
	if err != nil {
		return err
	}
	timestamp, err := tufmetadata.Timestamp().FromBytes(timestampBytes)
	if err != nil || timestamp.Signed.Version != state.MetadataVersion {
		return fmt.Errorf("published timestamp metadata is invalid")
	}
	if err := root.VerifyDelegate(tufmetadata.TIMESTAMP, timestamp); err != nil {
		return fmt.Errorf("verify published timestamp metadata: %w", err)
	}
	snapshotMeta := timestamp.Signed.Meta["snapshot.json"]
	if snapshotMeta == nil || snapshotMeta.Version != state.MetadataVersion || snapshotMeta.VerifyLengthHashes(snapshotBytes) != nil {
		return fmt.Errorf("published timestamp snapshot reference is invalid")
	}
	return nil
}

func recoverPluginRepositoryPublisherRotation(workspace string) error {
	journalPath := filepath.Join(workspace, "rotation.json")
	var journal pluginRepositoryPublisherRotationJournal
	if err := readPluginRepositoryJSON(journalPath, pluginRepositoryPublisherMaxStateBytes, &journal); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read repository key rotation journal: %w", err)
	}
	if journal.FormatVersion != pluginRepositoryPublisherFormatVersion || !pluginRepositoryTopLevelRole(journal.Role) ||
		journal.NewKeyVersion < 2 || journal.NewRootVersion < 2 || journal.State.RootVersion != journal.NewRootVersion ||
		journal.State.KeyVersions[journal.Role] != journal.NewKeyVersion || len(journal.PrivateKeyPEM) == 0 || len(journal.Root) == 0 {
		return fmt.Errorf("repository key rotation journal is invalid")
	}
	root, err := tufmetadata.Root().FromBytes(journal.Root)
	if err != nil || root.Signed.Version != journal.NewRootVersion || root.VerifyDelegate(tufmetadata.ROOT, root) != nil {
		return fmt.Errorf("repository key rotation root is invalid")
	}
	privateKey, err := parsePluginRepositoryPrivateKeyPEM(journal.PrivateKeyPEM)
	if err != nil {
		return fmt.Errorf("repository key rotation private key is invalid: %w", err)
	}
	metadataKey, err := tufmetadata.KeyFromPublicKey(privateKey.Public())
	if err != nil {
		return err
	}
	keyID, err := metadataKey.ID()
	if err != nil || !pluginRepositoryRoleContainsKey(root.Signed.Roles[journal.Role], keyID) {
		return fmt.Errorf("repository key rotation private key does not match the new root role")
	}
	var current pluginRepositoryPublisherState
	if err := readPluginRepositoryJSON(filepath.Join(workspace, pluginRepositoryPublisherStateFile), pluginRepositoryPublisherMaxStateBytes, &current); err != nil {
		return fmt.Errorf("read pre-rotation repository state: %w", err)
	}
	if current.RootVersion == journal.NewRootVersion {
		if !reflect.DeepEqual(current, journal.State) {
			return fmt.Errorf("repository key rotation state changed after commit")
		}
	} else {
		if journal.NewRootVersion != current.RootVersion+1 || journal.NewKeyVersion != current.KeyVersions[journal.Role]+1 {
			return fmt.Errorf("repository key rotation versions are not consecutive")
		}
		oldRoot, _, err := loadPluginRepositoryPublisherRoot(workspace, current.RootVersion)
		if err != nil {
			return err
		}
		if err := oldRoot.VerifyDelegate(tufmetadata.ROOT, root); err != nil {
			return fmt.Errorf("repository key rotation is not authorized by the previous root: %w", err)
		}
	}
	keyPath := pluginRepositoryPublisherKeyPath(workspace, journal.Role, journal.NewKeyVersion)
	if err := writePluginRepositoryPublisherFileIdempotent(keyPath, journal.PrivateKeyPEM, 0o600); err != nil {
		return err
	}
	rootPath := pluginRepositoryPublisherRootPath(workspace, journal.NewRootVersion)
	if err := writePluginRepositoryPublisherFileIdempotent(rootPath, journal.Root, 0o600); err != nil {
		return err
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(workspace, pluginRepositoryPublisherStateFile), journal.State, true); err != nil {
		return err
	}
	return os.Remove(journalPath)
}

func writePluginRepositoryPublisherFileIdempotent(path string, data []byte, mode os.FileMode) error {
	if _, current, _, err := readPluginCLIRegularFile(path, pluginRepositoryPublisherMaxStateBytes); err == nil {
		if !reflect.DeepEqual(current, data) {
			return fmt.Errorf("repository recovery path %s contains different data", filepath.Base(path))
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writePluginPackageFileAtomic(path, data, false, mode)
}

func pluginRepositoryPublisherDirectoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("repository publisher path %s is not a regular directory", path)
	}
	return true, nil
}

func pluginRepositoryTopLevelRoles() []string {
	return []string{tufmetadata.ROOT, tufmetadata.TARGETS, tufmetadata.SNAPSHOT, tufmetadata.TIMESTAMP}
}

func pluginRepositoryTopLevelRole(role string) bool {
	for _, candidate := range pluginRepositoryTopLevelRoles() {
		if role == candidate {
			return true
		}
	}
	return false
}

func pluginRepositoryRoleContainsKey(role *tufmetadata.Role, keyID string) bool {
	if role == nil || keyID == "" {
		return false
	}
	for _, candidate := range role.KeyIDs {
		if candidate == keyID {
			return true
		}
	}
	return false
}

func pluginRepositoryPublisherKeyPath(workspace, role string, version int64) string {
	return filepath.Join(workspace, "keys", fmt.Sprintf("%s-%d.pem", role, version))
}

func pluginRepositoryPublisherRootPath(workspace string, version int64) string {
	return filepath.Join(workspace, "roots", fmt.Sprintf("%d.root.json", version))
}

func loadPluginRepositoryPublisherRoleKey(workspace string, state pluginRepositoryPublisherState, role string) (ed25519.PrivateKey, error) {
	if !pluginRepositoryTopLevelRole(role) || state.KeyVersions[role] < 1 {
		return nil, fmt.Errorf("repository role key state is invalid")
	}
	key, err := loadPluginPackagePrivateKey(pluginRepositoryPublisherKeyPath(workspace, role, state.KeyVersions[role]))
	if err != nil {
		return nil, fmt.Errorf("load repository %s key: %w", role, err)
	}
	return key, nil
}

func loadPluginRepositoryPublisherRoot(workspace string, version int64) (*tufmetadata.Metadata[tufmetadata.RootType], []byte, error) {
	if version < 1 {
		return nil, nil, fmt.Errorf("repository root version is invalid")
	}
	_, data, _, err := readPluginCLIRegularFile(pluginRepositoryPublisherRootPath(workspace, version), pluginRepositoryMaxRootBytes)
	if err != nil {
		return nil, nil, err
	}
	root, err := tufmetadata.Root().FromBytes(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse repository root %d: %w", version, err)
	}
	return root, data, nil
}

func marshalPluginRepositoryPrivateKey(privateKey ed25519.PrivateKey) ([]byte, error) {
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), nil
}

func parsePluginRepositoryPrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

func writePluginRepositoryPrivateKey(path string, privateKey ed25519.PrivateKey) error {
	data, err := marshalPluginRepositoryPrivateKey(privateKey)
	if err != nil {
		return err
	}
	return writePluginPackageFileAtomic(path, data, false, 0o600)
}

func signPluginRepositoryMetadata[T tufmetadata.Roles](metadata *tufmetadata.Metadata[T], privateKey ed25519.PrivateKey) error {
	signer, err := signature.LoadSigner(privateKey, crypto.Hash(0))
	if err != nil {
		return err
	}
	if _, err := metadata.Sign(signer); err != nil {
		return err
	}
	return nil
}

func inspectPluginRepositoryPublisherArchive(path string) (pluginPackageCLIArchiveInfo, LoadedPlugin, []byte, error) {
	absArchive, data, info, err := readPluginCLIRegularFile(path, pluginPackageMaxArchiveBytes)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, LoadedPlugin{}, nil, err
	}
	digest := sha256.Sum256(data)
	tempRoot, err := os.MkdirTemp("", "veer-plugin-repository-*")
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, LoadedPlugin{}, nil, err
	}
	defer os.RemoveAll(tempRoot)
	pluginRoot, err := extractPluginPackageArchive(absArchive, tempRoot)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, LoadedPlugin{}, nil, err
	}
	plugin, err := validatePluginPackageSource(pluginRoot)
	if err != nil {
		return pluginPackageCLIArchiveInfo{}, LoadedPlugin{}, nil, err
	}
	if filepath.Base(pluginRoot) != plugin.ID {
		return pluginPackageCLIArchiveInfo{}, LoadedPlugin{}, nil, fmt.Errorf("plugin package directory %q does not match manifest id %q", filepath.Base(pluginRoot), plugin.ID)
	}
	archive := pluginPackageCLIArchiveInfo{
		PluginID: plugin.ID, Version: plugin.Version, Archive: absArchive,
		ArchiveSHA256: hex.EncodeToString(digest[:]), Bytes: info.Size(),
	}
	return archive, plugin, data, nil
}

func sortPluginRepositoryPublisherTargets(targets []pluginRepositoryPublisherTarget) {
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].PluginID != targets[j].PluginID {
			return targets[i].PluginID < targets[j].PluginID
		}
		leftVersion, _ := semver.StrictNewVersion(targets[i].Version)
		rightVersion, _ := semver.StrictNewVersion(targets[j].Version)
		if !leftVersion.Equal(rightVersion) {
			return leftVersion.LessThan(rightVersion)
		}
		return targets[i].Channel < targets[j].Channel
	})
}

func pluginRepositoryPublisherTargetPath(target pluginRepositoryPublisherTarget) string {
	return "plugins/" + target.Channel + "/" + target.PluginID + "/" + target.Version + "/package.tar.gz"
}

func (target pluginRepositoryPublisherTarget) pluginRepositoryMetadata() pluginRepositoryTargetMetadata {
	return pluginRepositoryTargetMetadata{
		FormatVersion: pluginRepositoryTargetFormatVersion, Kind: pluginRepositoryTargetKind,
		PluginID: target.PluginID, Name: target.Name, Description: target.Description,
		Version: target.Version, Channel: target.Channel, Stability: target.Stability,
		Compatibility: clonePluginCompatibility(target.Compatibility),
		Dependencies:  append([]PluginDependency(nil), target.Dependencies...),
		Conflicts:     append([]PluginConflict(nil), target.Conflicts...),
		Revoked:       target.Revoked, RevocationReason: target.RevocationReason,
	}
}
