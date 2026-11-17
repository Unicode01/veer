package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestHotRestartOverallVerdict(t *testing.T) {
	t.Parallel()

	engines := func(verdicts ...string) []hotRestartEngineReport {
		out := make([]hotRestartEngineReport, 0, len(verdicts))
		for _, verdict := range verdicts {
			out = append(out, hotRestartEngineReport{Verdict: verdict})
		}
		return out
	}
	tests := []struct {
		engines []hotRestartEngineReport
		want    string
	}{
		{nil, hotRestartVerdictNone},
		{engines(hotRestartVerdictNone, hotRestartVerdictNone), hotRestartVerdictNone},
		{engines(hotRestartVerdictHot, hotRestartVerdictNone), hotRestartVerdictHot},
		{engines(hotRestartVerdictHot, hotRestartVerdictUnknown), hotRestartVerdictUnknown},
		{engines(hotRestartVerdictUnknown, hotRestartVerdictCold), hotRestartVerdictCold},
		{engines(hotRestartVerdictCold, hotRestartVerdictHot), hotRestartVerdictCold},
	}
	for _, tt := range tests {
		if got := hotRestartOverallVerdict(tt.engines); got != tt.want {
			t.Errorf("hotRestartOverallVerdict(%+v) = %q, want %q", tt.engines, got, tt.want)
		}
	}
}

func TestWriteHotRestartCheckReport(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writeHotRestartCheckReport(&out, hotRestartCheckReport{
		Verdict:      hotRestartVerdictCold,
		Config:       "/opt/veer/config.json",
		TrafficStats: true,
		Engines: []hotRestartEngineReport{
			{
				Engine:  "tc",
				Source:  hotRestartSourceRunning,
				PID:     4242,
				Verdict: hotRestartVerdictCold,
				Reason:  "flows_old_v4 cannot be adopted",
				Maps: []hotRestartMapReport{
					{Name: "flows_old_v4", From: "flows_v4", Reason: "value_size=64 but current object expects 104"},
					{Name: "stats_v4", Compatible: true, Preserved: &hotRestartMapLayout{Type: "PerCPUHash", KeySize: 4, ValueSize: 32, MaxEntries: 1024}},
				},
			},
			{Engine: "xdp", Source: hotRestartSourceNone, Verdict: hotRestartVerdictNone, Reason: "no running xdp dataplane and no pinned handoff"},
		},
	})
	text := out.String()
	for _, want := range []string{
		"config:   /opt/veer/config.json (kernel_traffic_stats on)\n",
		"tc:       running daemon, pid 4242\n",
		"INCOMPATIBLE  flows_v4 -> flows_old_v4",
		"value_size=64 but current object expects 104\n",
		"ok            stats_v4",
		"PerCPUHash key=4 value=32 max_entries=1024 flags=0x0\n",
		"  => cold: flows_old_v4 cannot be adopted\n",
		"xdp:      nothing to preserve\n",
		"  => nothing pinned: no running xdp dataplane and no pinned handoff\n",
		"verdict:  cold - the next hot restart falls back to fresh maps (cold restart)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report text is missing %q:\n%s", want, text)
		}
	}
}

func TestRunHotRestartCLIDispatch(t *testing.T) {
	t.Parallel()

	if handled, err := runHotRestartCLI([]string{"kfuncs", "status"}, nil, nil); handled || err != nil {
		t.Fatalf("other command = %t, %v; want not handled", handled, err)
	}
	var stdout, stderr bytes.Buffer
	if handled, err := runHotRestartCLI([]string{"hot-restart", "help"}, &stdout, &stderr); !handled || err != nil || !strings.Contains(stdout.String(), "veer hot-restart check [--json]") {
		t.Fatalf("help = %t, %v, %q; want usage on stdout", handled, err, stdout.String())
	}
	if handled, err := runHotRestartCLI([]string{"hot-restart"}, &stdout, &stderr); !handled || err == nil {
		t.Fatalf("missing subcommand = %t, %v; want an error", handled, err)
	}
	if handled, err := runHotRestartCLI([]string{"hot-restart", "verify"}, &stdout, &stderr); !handled || err == nil || !strings.Contains(err.Error(), `unknown hot-restart subcommand "verify"`) {
		t.Fatalf("unknown subcommand = %t, %v; want an error naming it", handled, err)
	}
	if handled, err := runHotRestartCLI([]string{"hot-restart", "check", "extra"}, &stdout, &stderr); !handled || err == nil || !strings.Contains(err.Error(), `unexpected argument "extra"`) {
		t.Fatalf("stray argument = %t, %v; want an error naming it", handled, err)
	}
}
