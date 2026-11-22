package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// `veer plugin preflight` tells, before an upgrade, which installed plugins
// the binary about to be installed cannot run. deploy.sh runs it with the new
// binary before it changes anything: it replaces the plugins it can from the
// release's plugin bundle and otherwise stops.

const (
	pluginPreflightOK      = "ok"
	pluginPreflightBlocked = "blocked"
	pluginPreflightWarning = "warning"

	// A JavaScript control script, which only goja-based versions ran.
	pluginPreflightControlScript = "control_script"
	// A native plugin without a library build for this host.
	pluginPreflightNoLibrary = "no_library"
	// A native plugin, and this binary carries no plugin worker to run it.
	pluginPreflightNoWorker = "no_worker"
	// The catalog reports an error for the plugin. It may have had the same
	// error before the upgrade, so this only warns.
	pluginPreflightCatalogError = "catalog_error"
)

type pluginPreflightReport struct {
	// Verdict is ok or blocked.
	Verdict        string                  `json:"verdict"`
	Config         string                  `json:"config,omitempty"`
	PluginsEnabled bool                    `json:"plugins_enabled"`
	PluginsDir     string                  `json:"plugins_dir,omitempty"`
	HostTriple     string                  `json:"host_triple,omitempty"`
	Worker         bool                    `json:"worker"`
	Notes          []string                `json:"notes,omitempty"`
	Plugins        []pluginPreflightPlugin `json:"plugins"`
}

type pluginPreflightPlugin struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	// Dir is the plugin's directory name under plugins_dir.
	Dir    string `json:"dir,omitempty"`
	Status string `json:"status"`
	// Problem is one of the pluginPreflight* codes; deploy.sh acts on it.
	Problem string `json:"problem,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func runPluginPreflightCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin preflight", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	configPath := flags.String("config", "", "config of the daemon (default: <install-dir>/config.json)")
	if err := flags.Parse(args); err != nil {
		return cliFlagError(err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	_, dir, err := kernelHelperCLIInstallDir(*installDir)
	if err != nil {
		return err
	}
	config := *configPath
	if config == "" {
		config = filepath.Join(dir, "config.json")
	}
	report, err := inspectPluginPreflight(dir, config)
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	writePluginPreflightReport(stdout, report)
	return nil
}

// inspectPluginPreflight checks every plugin directory under the configured
// plugins_dir, enabled or not: the plugin state lives in the database, which
// this check does not open. It reads the config without validating it, so a
// config that predates this binary still names its plugins.
func inspectPluginPreflight(installDir, configPath string) (pluginPreflightReport, error) {
	report := pluginPreflightReport{Verdict: pluginPreflightOK, HostTriple: pluginNativeHostTriple(), Plugins: []pluginPreflightPlugin{}}
	data, err := os.ReadFile(configPath)
	if errors.Is(err, fs.ErrNotExist) {
		report.Notes = append(report.Notes, fmt.Sprintf("no config at %s; plugins are off by default", configPath))
		return report, nil
	}
	if err != nil {
		return report, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return report, fmt.Errorf("read config %s: %w", configPath, err)
	}
	report.Config = configPath
	report.PluginsEnabled = cfg.PluginsEnabled()
	pluginsDir := normalizePluginsDir(cfg.PluginsDir)
	if !filepath.IsAbs(pluginsDir) {
		// The service runs in the install directory.
		pluginsDir = filepath.Join(installDir, pluginsDir)
	}
	report.PluginsDir = pluginsDir
	if !report.PluginsEnabled {
		report.Notes = append(report.Notes, "plugins_enabled is off; installed plugins do not run")
		return report, nil
	}
	cfg.PluginsDir = pluginsDir
	report.Worker = pluginNativeWorkerShipped(installDir)
	catalog := loadPluginCatalog(&cfg)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin {
			continue
		}
		entry := classifyPluginPreflight(plugin, pluginsDir, report.HostTriple, report.Worker)
		if entry.Status == pluginPreflightBlocked {
			report.Verdict = pluginPreflightBlocked
		}
		report.Plugins = append(report.Plugins, entry)
	}
	return report, nil
}

func classifyPluginPreflight(plugin LoadedPlugin, pluginsDir, triple string, worker bool) pluginPreflightPlugin {
	entry := pluginPreflightPlugin{ID: plugin.ID, Version: plugin.Version, Dir: plugin.Source, Status: pluginPreflightOK}
	blocked := func(problem, reason string) pluginPreflightPlugin {
		entry.Status, entry.Problem, entry.Reason = pluginPreflightBlocked, problem, reason
		return entry
	}
	if plugin.Control != nil && strings.TrimSpace(plugin.Control.Main) != "" {
		return blocked(pluginPreflightControlScript, fmt.Sprintf("control script %s: this version runs native plugin libraries only", plugin.Control.Main))
	}
	if plugin.rootDir == "" && plugin.Source != "" {
		// The manifest did not load at all; an old JavaScript plugin may
		// still be recognizable from its raw control section.
		if id, version, main, ok := pluginPreflightRawControlScript(filepath.Join(pluginsDir, plugin.Source)); ok {
			entry.ID, entry.Version = id, version
			return blocked(pluginPreflightControlScript, fmt.Sprintf("control script %s: this version runs native plugin libraries only", main))
		}
	}
	if plugin.Status == pluginStatusError {
		entry.Status, entry.Problem, entry.Reason = pluginPreflightWarning, pluginPreflightCatalogError, plugin.Error
		return entry
	}
	if !pluginUsesNativeControl(plugin) || pluginNativeDeclarativeOnly(plugin) {
		return entry
	}
	if plugin.nativeLibraryPath == "" {
		builds := make([]string, 0, len(plugin.Control.Library))
		for build := range plugin.Control.Library {
			builds = append(builds, build)
		}
		sort.Strings(builds)
		host := triple
		if host == "" {
			host = "this platform"
		}
		return blocked(pluginPreflightNoLibrary, fmt.Sprintf("no library build for %s (builds: %s)", host, strings.Join(builds, ", ")))
	}
	if !worker {
		return blocked(pluginPreflightNoWorker, fmt.Sprintf("this veer binary carries no plugin worker for %s", triple))
	}
	return entry
}

// pluginPreflightRawControlScript reads the control script a manifest names
// when the catalog could not load the manifest.
func pluginPreflightRawControlScript(dir string) (id, version, main string, ok bool) {
	data, err := os.ReadFile(filepath.Join(dir, pluginManifestFile))
	if err != nil {
		return "", "", "", false
	}
	var raw struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Control *struct {
			Main string `json:"main"`
		} `json:"control"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.Control == nil || strings.TrimSpace(raw.Control.Main) == "" {
		return "", "", "", false
	}
	id = strings.TrimSpace(raw.ID)
	if id == "" {
		id = filepath.Base(dir)
	}
	return id, raw.Version, raw.Control.Main, true
}

// pluginNativeWorkerShipped reports whether veer installed in installDir
// finds a plugin worker: the one built into this binary for the host, or a
// veer-plugin-worker file next to it.
func pluginNativeWorkerShipped(installDir string) bool {
	if triple := pluginNativeHostTriple(); triple != "" {
		if _, err := fs.Stat(embeddedPluginNativeWorkers, "pluginworker/"+triple+"/veer-plugin-worker"); err == nil {
			return true
		}
	}
	info, err := os.Stat(filepath.Join(installDir, "veer-plugin-worker"))
	return err == nil && info.Mode().IsRegular()
}

func writePluginPreflightReport(w io.Writer, report pluginPreflightReport) {
	if report.Config != "" {
		state := "off"
		if report.PluginsEnabled {
			state = "on"
		}
		fmt.Fprintf(w, "config:   %s (plugins_enabled %s, plugins_dir %s)\n", report.Config, state, report.PluginsDir)
	}
	for _, note := range report.Notes {
		fmt.Fprintf(w, "note:     %s\n", note)
	}
	if report.PluginsEnabled {
		worker := "none"
		if report.Worker {
			worker = "yes"
		}
		host := report.HostTriple
		if host == "" {
			host = "unsupported platform"
		}
		fmt.Fprintf(w, "worker:   %s (host %s)\n", worker, host)
	}
	for _, plugin := range report.Plugins {
		status := plugin.Status
		if status == pluginPreflightBlocked {
			status = "BLOCKED"
		}
		line := fmt.Sprintf("  %-8s  %s %s", status, plugin.ID, plugin.Version)
		if plugin.Reason != "" {
			line += ": " + plugin.Reason
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	blocked := 0
	for _, plugin := range report.Plugins {
		if plugin.Status == pluginPreflightBlocked {
			blocked++
		}
	}
	if report.Verdict == pluginPreflightBlocked {
		fmt.Fprintf(w, "verdict:  blocked - %d installed plugin(s) cannot run on this version\n", blocked)
		return
	}
	fmt.Fprintln(w, "verdict:  ok - every installed plugin can run on this version")
}
