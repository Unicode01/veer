package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const pluginRepositoryPlanMaxAttempts = 4096

type pluginRepositoryPlanChoice struct {
	Target    *PluginRepositoryTarget
	Version   string
	Installed bool
}

type pluginRepositoryPlanSolver struct {
	manager     *pluginPackageManager
	repository  PluginRepository
	channel     string
	catalog     PluginRepositoryCatalog
	installed   map[string]LoadedPlugin
	policies    map[string]PluginRepositoryPolicy
	rootID      string
	rootVersion string
	attempts    int
	lastFailure string
}

func (m *pluginPackageManager) PrepareRepositoryInstallPlan(request PluginRepositoryInstallPlanRequest) (PluginRepositoryInstallPlan, error) {
	repository, err := m.loadPluginRepository(request.RepositoryID)
	if err != nil {
		return PluginRepositoryInstallPlan{}, err
	}
	pluginID := strings.TrimSpace(strings.ToLower(request.PluginID))
	if !pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID) {
		return PluginRepositoryInstallPlan{}, fmt.Errorf("plugin id is invalid")
	}
	requestedVersion := strings.TrimSpace(request.Version)
	if requestedVersion != "" {
		normalized, normalizeErr := normalizePluginSemanticVersion(requestedVersion)
		if normalizeErr != nil || normalized != requestedVersion {
			return PluginRepositoryInstallPlan{}, fmt.Errorf("plugin version must be strict SemVer")
		}
	}
	channel, requestedVersion, policy, err := m.effectiveRepositorySelection(repository, pluginID, requestedVersion)
	if err != nil {
		return PluginRepositoryInstallPlan{}, err
	}
	if policy != nil && policy.RepositoryID == repository.ID && policy.Hold {
		installed := pluginRepositoryInstalledPlugins(m)[pluginID]
		if installed.ID != "" && requestedVersion != "" && requestedVersion != installed.Version {
			return PluginRepositoryInstallPlan{}, fmt.Errorf("plugin %s is on hold at version %s", pluginID, installed.Version)
		}
	}
	policies, err := m.repositoryPoliciesByPlugin()
	if err != nil {
		return PluginRepositoryInstallPlan{}, err
	}
	catalog, client, err := m.refreshPluginRepository(repository)
	if err != nil {
		return PluginRepositoryInstallPlan{}, err
	}
	solver := pluginRepositoryPlanSolver{
		manager: m, repository: repository, channel: channel, catalog: catalog,
		installed: pluginRepositoryInstalledPlugins(m), policies: policies, rootID: pluginID, rootVersion: requestedVersion,
	}
	choices, err := solver.solve()
	if err != nil {
		return PluginRepositoryInstallPlan{}, err
	}
	targets := make([]PluginRepositoryTarget, 0, len(choices))
	reused := make([]PluginRepositoryInstallPlanReuse, 0, len(choices))
	for pluginID, choice := range choices {
		if choice.Installed {
			reused = append(reused, PluginRepositoryInstallPlanReuse{PluginID: pluginID, Version: choice.Version})
			continue
		}
		if choice.Target != nil {
			targets = append(targets, *choice.Target)
		}
	}
	if len(targets) > pluginPackageBatchMaxStages {
		return PluginRepositoryInstallPlan{}, fmt.Errorf("repository dependency plan requires %d package changes; maximum is %d", len(targets), pluginPackageBatchMaxStages)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].PluginID < targets[j].PluginID })
	sort.Slice(reused, func(i, j int) bool { return reused[i].PluginID < reused[j].PluginID })

	stages := make([]PluginPackageStage, 0, len(targets))
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		for _, stage := range stages {
			_ = removePluginPackageManagedPath(m.stateRoot, stage.stageDir)
		}
	}()
	deferredRelationships := len(targets) > 1
	for _, target := range targets {
		stage, stageErr := m.stagePluginRepositoryTarget(repository, catalog, client, target, deferredRelationships)
		if stageErr != nil {
			return PluginRepositoryInstallPlan{}, fmt.Errorf("stage repository dependency %s: %w", target.PluginID, stageErr)
		}
		stages = append(stages, stage)
	}
	if len(stages) > 0 {
		requests := make([]PluginPackageApplyRequest, 0, len(stages))
		pluginIDs := make([]string, 0, len(stages))
		for _, stage := range stages {
			requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest})
			pluginIDs = append(pluginIDs, stage.PluginID)
		}
		if err := m.ensurePluginPackageMutationAllowed(pluginIDs); err != nil {
			return PluginRepositoryInstallPlan{}, err
		}
		candidates, err := m.validatePluginPackageBatchRequest(PluginPackageBatchApplyRequest{Stages: requests})
		if err != nil {
			return PluginRepositoryInstallPlan{}, fmt.Errorf("validate repository dependency stages: %w", err)
		}
		if err := m.validatePluginPackageBatchCatalog(candidates); err != nil {
			return PluginRepositoryInstallPlan{}, fmt.Errorf("validate repository dependency plan: %w", err)
		}
	}
	cleanup = false
	return PluginRepositoryInstallPlan{
		RepositoryID: repository.ID, Channel: channel,
		RequestedPlugin: pluginID, RequestedVersion: requestedVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Stages: stages, Reused: reused,
	}, nil
}

func pluginRepositoryInstalledPlugins(m *pluginPackageManager) map[string]LoadedPlugin {
	installed := make(map[string]LoadedPlugin)
	if m == nil {
		return installed
	}
	catalog := loadPluginCatalogWithControlRegistrationAndState(pluginPackageValidationConfig(m.cfg, m.pluginsRoot), m.db)
	for _, plugin := range catalog.Plugins {
		if !plugin.Builtin {
			installed[plugin.ID] = plugin
		}
	}
	return installed
}

func (s *pluginRepositoryPlanSolver) solve() (map[string]pluginRepositoryPlanChoice, error) {
	choices, ok := s.search(make(map[string]pluginRepositoryPlanChoice))
	if ok {
		return choices, nil
	}
	if s.lastFailure == "" {
		s.lastFailure = "no compatible dependency graph is available"
	}
	return nil, fmt.Errorf("resolve repository install plan for %s: %s", s.rootID, s.lastFailure)
}

func (s *pluginRepositoryPlanSolver) search(choices map[string]pluginRepositoryPlanChoice) (map[string]pluginRepositoryPlanChoice, bool) {
	s.attempts++
	if s.attempts > pluginRepositoryPlanMaxAttempts {
		s.lastFailure = fmt.Sprintf("dependency solver exceeded %d attempts", pluginRepositoryPlanMaxAttempts)
		return nil, false
	}
	requirements := s.reachableRequirements(choices)
	if len(requirements) > pluginPackageBatchMaxStages+len(s.installed) {
		s.lastFailure = "dependency graph exceeds the supported plugin count"
		return nil, false
	}
	for pluginID := range choices {
		if _, required := requirements[pluginID]; !required {
			delete(choices, pluginID)
		}
	}
	ids := make([]string, 0, len(requirements))
	for pluginID := range requirements {
		ids = append(ids, pluginID)
	}
	sort.Strings(ids)
	for _, pluginID := range ids {
		constraints := requirements[pluginID]
		choice, selected := choices[pluginID]
		if selected && pluginRepositoryVersionSatisfiesAll(choice.Version, constraints) {
			continue
		}
		domains := s.domains(pluginID, constraints)
		if len(domains) == 0 {
			s.lastFailure = fmt.Sprintf("plugin %s has no trusted version satisfying %s", pluginID, strings.Join(constraints, " and "))
			return nil, false
		}
		for _, domain := range domains {
			next := make(map[string]pluginRepositoryPlanChoice, len(choices)+1)
			for id, current := range choices {
				next[id] = current
			}
			next[pluginID] = domain
			if solved, ok := s.search(next); ok {
				return solved, true
			}
		}
		return nil, false
	}
	return choices, true
}

func (s *pluginRepositoryPlanSolver) reachableRequirements(choices map[string]pluginRepositoryPlanChoice) map[string][]string {
	constraint := "*"
	if s.rootVersion != "" {
		constraint = "=" + s.rootVersion
	}
	requirements := map[string][]string{s.rootID: {constraint}}
	queue := []string{s.rootID}
	queued := map[string]bool{s.rootID: true}
	for len(queue) > 0 {
		pluginID := queue[0]
		queue = queue[1:]
		queued[pluginID] = false
		choice, selected := choices[pluginID]
		if !selected || choice.Target == nil {
			continue
		}
		for _, dependency := range choice.Target.Dependencies {
			if dependency.Optional {
				continue
			}
			constraint := dependency.Version
			if constraint == "" {
				constraint = "*"
			}
			if pluginRepositoryAppendConstraint(requirements, dependency.ID, constraint) && !queued[dependency.ID] {
				queue = append(queue, dependency.ID)
				queued[dependency.ID] = true
			}
		}
	}
	return requirements
}

func pluginRepositoryAppendConstraint(requirements map[string][]string, pluginID, constraint string) bool {
	for _, existing := range requirements[pluginID] {
		if existing == constraint {
			return false
		}
	}
	requirements[pluginID] = append(requirements[pluginID], constraint)
	sort.Strings(requirements[pluginID])
	return true
}

func (s *pluginRepositoryPlanSolver) domains(pluginID string, constraints []string) []pluginRepositoryPlanChoice {
	installed, hasInstalled := s.installed[pluginID]
	channel := s.channel
	policy, hasPolicy := s.policies[pluginID]
	if hasPolicy && policy.RepositoryID == s.repository.ID {
		channel = policy.Channel
		if policy.PinnedVersion != "" {
			constraints = append(append([]string(nil), constraints...), "="+policy.PinnedVersion)
		}
	}
	keep := pluginRepositoryPlanChoice{}
	canKeep := hasInstalled && pluginAvailableForRelationship(installed) && pluginRepositoryVersionSatisfiesAll(installed.Version, constraints)
	if canKeep {
		keep = pluginRepositoryPlanChoice{Version: installed.Version, Installed: true}
	}
	if hasPolicy && policy.RepositoryID == s.repository.ID && policy.Hold && hasInstalled {
		if canKeep {
			return []pluginRepositoryPlanChoice{keep}
		}
		return nil
	}
	targets := make([]PluginRepositoryTarget, 0)
	for _, target := range s.catalog.Targets {
		if target.PluginID != pluginID || target.Channel != channel || target.Revoked ||
			!pluginRepositoryVersionSatisfiesAll(target.Version, constraints) {
			continue
		}
		probe := LoadedPlugin{PluginManifest: PluginManifest{Compatibility: clonePluginCompatibility(target.Compatibility)}}
		if err := checkPluginCompatibility(probe, currentPluginHostEnvironment()); err != nil {
			continue
		}
		if hasInstalled && target.Version == installed.Version {
			continue
		}
		if err := s.manager.checkPluginRepositoryAntiDowngrade(s.repository, target); err != nil {
			continue
		}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		left, _ := semver.StrictNewVersion(targets[i].Version)
		right, _ := semver.StrictNewVersion(targets[j].Version)
		return left.GreaterThan(right)
	})
	domains := make([]pluginRepositoryPlanChoice, 0, len(targets)+1)
	if pluginID != s.rootID && canKeep {
		domains = append(domains, keep)
	}
	for i := range targets {
		target := targets[i]
		domains = append(domains, pluginRepositoryPlanChoice{Target: &target, Version: target.Version})
	}
	if pluginID == s.rootID && canKeep {
		domains = append(domains, keep)
	}
	return domains
}

func pluginRepositoryVersionSatisfiesAll(version string, constraints []string) bool {
	for _, constraint := range constraints {
		if !pluginVersionSatisfies(version, constraint) {
			return false
		}
	}
	return true
}
