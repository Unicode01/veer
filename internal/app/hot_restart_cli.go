package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	hotRestartVerdictHot     = "hot"
	hotRestartVerdictCold    = "cold"
	hotRestartVerdictNone    = "none"
	hotRestartVerdictUnknown = "unknown"

	hotRestartSourceRunning = "running"
	hotRestartSourcePinned  = "pinned"
	hotRestartSourceNone    = "none"
)

// hotRestartCheckReport is what `veer hot-restart check` prints.
type hotRestartCheckReport struct {
	// Verdict is hot, cold, none (nothing to preserve) or unknown.
	Verdict      string                   `json:"verdict"`
	Config       string                   `json:"config,omitempty"`
	TrafficStats bool                     `json:"traffic_stats"`
	Notes        []string                 `json:"notes,omitempty"`
	Engines      []hotRestartEngineReport `json:"engines"`
}

type hotRestartEngineReport struct {
	Engine string `json:"engine"`
	// Source is running (the daemon's live maps, which it pins when it
	// stops for a hot restart), pinned (a handoff waiting for a successor) or
	// none.
	Source  string                `json:"source"`
	PID     int                   `json:"pid,omitempty"`
	Path    string                `json:"path,omitempty"`
	Verdict string                `json:"verdict"`
	Reason  string                `json:"reason,omitempty"`
	Notes   []string              `json:"notes,omitempty"`
	Maps    []hotRestartMapReport `json:"maps,omitempty"`
}

type hotRestartMapReport struct {
	// Name is the map of the new object that adopts the preserved map.
	Name string `json:"name"`
	// From is the preserved map's own name when it is adopted under another
	// one: a successor moves active flow banks to the old bank when no
	// migration is draining.
	From       string               `json:"from,omitempty"`
	Compatible bool                 `json:"compatible"`
	Reason     string               `json:"reason,omitempty"`
	Preserved  *hotRestartMapLayout `json:"preserved,omitempty"`
	Current    *hotRestartMapLayout `json:"current,omitempty"`
}

type hotRestartMapLayout struct {
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
	Flags      uint32 `json:"flags"`
}

type hotRestartCheckOptions struct {
	// InstallDir holds the daemon's runtime state unless the environment
	// names another directory, as deploy.sh does.
	InstallDir string
	ConfigPath string
	SkipStats  bool
}

func runHotRestartCLI(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "hot-restart" {
		return false, nil
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) < 2 {
		writeHotRestartCLIUsage(stderr)
		return true, errors.New("hot-restart subcommand is required")
	}
	switch args[1] {
	case "check":
		return true, runHotRestartCheckCLI(args[2:], stdout, stderr)
	case "help", "-h", "--help":
		writeHotRestartCLIUsage(stdout)
		return true, nil
	}
	writeHotRestartCLIUsage(stderr)
	return true, fmt.Errorf("unknown hot-restart subcommand %q", args[1])
}

func writeHotRestartCLIUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  veer hot-restart check [--json] [--install-dir DIR] [--config FILE] [--no-inherit-stats]

check tells, before a restart, whether the next hot restart can adopt the
kernel maps the running daemon preserves (flows, NAT ports, rule stats) or
falls back to fresh maps, a cold restart that drops kernel NAT connections and
per-rule counters. It compares those maps with the objects embedded in this
binary, loaded with the settings in the config, using the rules the new
process applies. Run it as root with the binary about to be installed. It
changes nothing. --no-inherit-stats matches deploy.sh --no-inherit-stats.
`)
}

func runHotRestartCheckCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("hot-restart check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	configPath := flags.String("config", "", "config of the daemon (default: <install-dir>/config.json)")
	skipStats := flags.Bool("no-inherit-stats", false, "check a hot restart that does not keep the stats map")
	if err := flags.Parse(args); err != nil {
		return cliFlagError(err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if runtime.GOOS != "linux" {
		return errors.New("hot restart is Linux-only")
	}
	_, dir, err := kernelHelperCLIInstallDir(*installDir)
	if err != nil {
		return err
	}
	config := *configPath
	if config == "" {
		config = filepath.Join(dir, "config.json")
	}
	report, err := inspectHotRestart(hotRestartCheckOptions{InstallDir: dir, ConfigPath: config, SkipStats: *skipStats})
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	writeHotRestartCheckReport(stdout, report)
	return nil
}

// hotRestartOverallVerdict is cold when any engine goes cold, since that
// engine loses its state whatever the others do.
func hotRestartOverallVerdict(engines []hotRestartEngineReport) string {
	verdict := hotRestartVerdictNone
	for _, engine := range engines {
		switch engine.Verdict {
		case hotRestartVerdictCold:
			return hotRestartVerdictCold
		case hotRestartVerdictUnknown:
			verdict = hotRestartVerdictUnknown
		case hotRestartVerdictHot:
			if verdict == hotRestartVerdictNone {
				verdict = hotRestartVerdictHot
			}
		}
	}
	return verdict
}

func hotRestartVerdictSummary(verdict string) string {
	switch verdict {
	case hotRestartVerdictHot:
		return "hot - the next hot restart adopts every preserved map"
	case hotRestartVerdictCold:
		return "cold - the next hot restart falls back to fresh maps (cold restart); kernel NAT connections and per-rule counters are lost"
	case hotRestartVerdictNone:
		return "nothing pinned - no kernel dataplane state to preserve"
	default:
		return "unknown - not every engine could be checked"
	}
}

func hotRestartEngineVerdictLabel(verdict string) string {
	if verdict == hotRestartVerdictNone {
		return "nothing pinned"
	}
	return verdict
}

func (layout *hotRestartMapLayout) String() string {
	if layout == nil {
		return "-"
	}
	return fmt.Sprintf("%s key=%d value=%d max_entries=%d flags=0x%x", layout.Type, layout.KeySize, layout.ValueSize, layout.MaxEntries, layout.Flags)
}

func writeHotRestartCheckReport(w io.Writer, report hotRestartCheckReport) {
	if report.Config != "" {
		stats := "off"
		if report.TrafficStats {
			stats = "on"
		}
		fmt.Fprintf(w, "config:   %s (kernel_traffic_stats %s)\n", report.Config, stats)
	}
	for _, note := range report.Notes {
		fmt.Fprintf(w, "note:     %s\n", note)
	}
	for _, engine := range report.Engines {
		source := "nothing to preserve"
		switch engine.Source {
		case hotRestartSourceRunning:
			source = fmt.Sprintf("running daemon, pid %d", engine.PID)
		case hotRestartSourcePinned:
			source = "pinned handoff in " + engine.Path
		}
		fmt.Fprintf(w, "%-9s %s\n", engine.Engine+":", source)
		for _, m := range engine.Maps {
			status, detail := "ok", m.Preserved.String()
			if !m.Compatible {
				status, detail = "INCOMPATIBLE", m.Reason
			}
			name := m.Name
			if m.From != "" && m.From != m.Name {
				name = m.From + " -> " + m.Name
			}
			fmt.Fprintf(w, "  %-12s  %-34s %s\n", status, name, detail)
		}
		for _, note := range engine.Notes {
			fmt.Fprintf(w, "  note: %s\n", note)
		}
		line := hotRestartEngineVerdictLabel(engine.Verdict)
		if engine.Reason != "" {
			line += ": " + engine.Reason
		}
		fmt.Fprintf(w, "  => %s\n", strings.TrimSpace(line))
	}
	fmt.Fprintf(w, "verdict:  %s\n", hotRestartVerdictSummary(report.Verdict))
}
