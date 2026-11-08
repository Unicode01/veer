package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
)

const veerCLIDatabaseFile = "forward.db"

func writeVeerUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  veer [--config FILE]     run the Veer daemon (the installed service does this)
  veer plugin <command>    plugin development, packaging, state backup and repositories
  veer kfuncs <command>    optional kernel helper module status and rebuild
  veer version [--json]    show build information
  veer help                show this help

Run "veer plugin help" or "veer kfuncs help" for command details.
`)
}

// runVeerInfoCLI handles the commands that only print.
func runVeerInfoCLI(args []string, buildNonce string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "help":
		writeVeerUsage(stdout)
		return true, nil
	case "version":
		flags := flag.NewFlagSet("version", flag.ContinueOnError)
		flags.SetOutput(stderr)
		asJSON := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return true, cliFlagError(err)
		}
		if flags.NArg() != 0 {
			return true, fmt.Errorf("unexpected argument %q", flags.Arg(0))
		}
		info := veerBuildInfo(buildNonce)
		if *asJSON {
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			return true, encoder.Encode(info)
		}
		writeVeerBuildInfo(stdout, info)
		return true, nil
	}
	return false, nil
}

type veerBuildInformation struct {
	Revision      string `json:"revision,omitempty"`
	Modified      bool   `json:"modified,omitempty"`
	CommitTime    string `json:"commit_time,omitempty"`
	BuildID       string `json:"build_id,omitempty"`
	GoVersion     string `json:"go_version"`
	Platform      string `json:"platform"`
	KernelHelper  bool   `json:"kernel_helper"`
	ModuleVersion string `json:"module_version,omitempty"`
}

func veerBuildInfo(buildNonce string) veerBuildInformation {
	info := veerBuildInformation{
		BuildID:      buildNonce,
		GoVersion:    runtime.Version(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		KernelHelper: optionalKernelModuleCompiled,
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if version := build.Main.Version; version != "" && version != "(devel)" {
		info.ModuleVersion = version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			info.Revision = setting.Value
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		case "vcs.time":
			info.CommitTime = setting.Value
		}
	}
	return info
}

// releaseVersionPattern matches tags such as v1.2.3 or v1.3.0-rc.1. Go stamps a
// tagged clean checkout with its tag; untagged or modified trees get
// pseudo-versions or "+dirty", which name no release.
var releaseVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)

func writeVeerBuildInfo(w io.Writer, info veerBuildInformation) {
	revision := info.Revision
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision != "" && info.Modified {
		revision += "-dirty"
	}
	label := "devel"
	switch {
	case releaseVersionPattern.MatchString(info.ModuleVersion):
		label = info.ModuleVersion
	case revision != "":
		label = revision
	case info.ModuleVersion != "":
		label = info.ModuleVersion
	}
	fmt.Fprintf(w, "veer %s\n", label)
	if revision != "" && label != revision {
		fmt.Fprintf(w, "  revision:       %s\n", revision)
	}
	if info.CommitTime != "" {
		fmt.Fprintf(w, "  commit time:    %s\n", info.CommitTime)
	}
	if info.BuildID != "" {
		fmt.Fprintf(w, "  build id:       %s\n", info.BuildID)
	}
	fmt.Fprintf(w, "  go:             %s %s\n", info.GoVersion, info.Platform)
	helper := "no"
	if info.KernelHelper {
		helper = "yes (veer kfuncs status)"
	}
	fmt.Fprintf(w, "  kernel helper:  %s\n", helper)
}

// cliFlagError treats -h/--help as success: the FlagSet already printed usage.
func cliFlagError(err error) error {
	if err == flag.ErrHelp {
		return nil
	}
	return err
}

// exitOnVeerCLIError prints a subcommand failure without log timestamps.
func exitOnVeerCLIError(command string, err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "veer %s: %v\n", command, err)
	os.Exit(1)
}

// applyInstallStateDefaults points plugin state commands at the deployed
// instance beside this binary when the current directory has no database.
// The service runs with its install directory as working directory, so this is
// what a command run from PATH means. Explicit flags always win.
func applyInstallStateDefaults(flags *flag.FlagSet, database, plugins *string, stderr io.Writer) {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	applyInstallStateDefaultsFrom(filepath.Dir(executable), flags, database, plugins, stderr)
}

func applyInstallStateDefaultsFrom(installDir string, flags *flag.FlagSet, database, plugins *string, stderr io.Writer) {
	set := map[string]bool{}
	flags.Visit(func(item *flag.Flag) { set[item.Name] = true })
	if set["database"] {
		return
	}
	if _, err := os.Stat(*database); err == nil {
		return
	}
	candidate := filepath.Join(installDir, veerCLIDatabaseFile)
	if info, err := os.Stat(candidate); err != nil || !info.Mode().IsRegular() {
		return
	}
	*database = candidate
	if !set["plugins-dir"] {
		*plugins = installPluginsDir(installDir)
	}
	fmt.Fprintf(stderr, "using the Veer install in %s (pass --database and --plugins-dir to override)\n", installDir)
}

// installPluginsDir resolves plugins_dir from the install's config.json the
// way the service does from its working directory.
func installPluginsDir(installDir string) string {
	value := defaultPluginsDir
	if data, err := os.ReadFile(filepath.Join(installDir, "config.json")); err == nil {
		var cfg struct {
			PluginsDir string `json:"plugins_dir"`
		}
		if json.Unmarshal(data, &cfg) == nil {
			value = normalizePluginsDir(cfg.PluginsDir)
		}
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(installDir, value)
	}
	return value
}
