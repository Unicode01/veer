package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVeerInfoCLIHelpAndVersion(t *testing.T) {
	if handled, _ := runVeerInfoCLI(nil, "", io.Discard, io.Discard); handled {
		t.Fatal("no arguments means the daemon")
	}
	if handled, _ := runVeerInfoCLI([]string{"--config", "x.json"}, "", io.Discard, io.Discard); handled {
		t.Fatal("daemon flags must fall through")
	}
	var out bytes.Buffer
	if handled, err := runVeerInfoCLI([]string{"help"}, "", &out, io.Discard); !handled || err != nil {
		t.Fatalf("help: handled=%v err=%v", handled, err)
	}
	for _, want := range []string{"veer plugin <command>", "veer kfuncs <command>", "veer version"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("usage lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "--worker") || strings.Contains(out.String(), "--plugin-host") {
		t.Fatal("internal worker flags must stay out of the usage")
	}

	out.Reset()
	if _, err := runVeerInfoCLI([]string{"version"}, "nonce123", &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "veer ") || !strings.Contains(out.String(), "build id:       nonce123") || !strings.Contains(out.String(), "kernel helper:") {
		t.Fatalf("version output:\n%s", out.String())
	}
	out.Reset()
	if _, err := runVeerInfoCLI([]string{"version", "--json"}, "nonce123", &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var info veerBuildInformation
	if err := json.Unmarshal(out.Bytes(), &info); err != nil || info.BuildID != "nonce123" || info.GoVersion == "" || info.KernelHelper != optionalKernelModuleCompiled {
		t.Fatalf("version JSON %v: %s", err, out.String())
	}
	if _, err := runVeerInfoCLI([]string{"version", "extra"}, "", io.Discard, io.Discard); err == nil {
		t.Fatal("version must reject positional arguments")
	}
	if _, err := runVeerInfoCLI([]string{"version", "-h"}, "", io.Discard, io.Discard); err != nil {
		t.Fatalf("version -h is not an error: %v", err)
	}
}

func TestKernelHelperCLIHelpFlagIsNotAnError(t *testing.T) {
	for _, command := range []string{"status", "build"} {
		if _, err := runKernelHelperCLI([]string{"kfuncs", command, "-h"}, io.Discard, io.Discard); err != nil {
			t.Fatalf("kfuncs %s -h: %v", command, err)
		}
	}
	if err := cliFlagError(errors.New("boom")); err == nil {
		t.Fatal("other flag errors must pass through")
	}
}

func TestApplyInstallStateDefaultsUsesInstallWhenRunFromPATH(t *testing.T) {
	install := t.TempDir()
	if err := os.WriteFile(filepath.Join(install, veerCLIDatabaseFile), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "config.json"), []byte(`{"plugins_dir":"custom-plugins"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	parse := func(args ...string) (*flag.FlagSet, *string, *string) {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		database := flags.String("database", veerCLIDatabaseFile, "")
		plugins := flags.String("plugins-dir", defaultPluginsDir, "")
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		return flags, database, plugins
	}

	flags, database, plugins := parse()
	var stderr bytes.Buffer
	applyInstallStateDefaultsFrom(install, flags, database, plugins, &stderr)
	if *database != filepath.Join(install, veerCLIDatabaseFile) || *plugins != filepath.Join(install, "custom-plugins") {
		t.Fatalf("defaults = %s, %s", *database, *plugins)
	}
	if !strings.Contains(stderr.String(), install) {
		t.Fatalf("the switch to the install must be announced: %q", stderr.String())
	}

	flags, database, plugins = parse("--plugins-dir", "/srv/plugins")
	applyInstallStateDefaultsFrom(install, flags, database, plugins, io.Discard)
	if *database != filepath.Join(install, veerCLIDatabaseFile) || *plugins != "/srv/plugins" {
		t.Fatalf("explicit --plugins-dir must win: %s, %s", *database, *plugins)
	}

	flags, database, plugins = parse("--database", "other.db")
	applyInstallStateDefaultsFrom(install, flags, database, plugins, io.Discard)
	if *database != "other.db" || *plugins != defaultPluginsDir {
		t.Fatalf("explicit --database must keep every default: %s, %s", *database, *plugins)
	}

	if err := os.WriteFile(veerCLIDatabaseFile, []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags, database, plugins = parse()
	applyInstallStateDefaultsFrom(install, flags, database, plugins, io.Discard)
	if *database != veerCLIDatabaseFile || *plugins != defaultPluginsDir {
		t.Fatalf("a database in the current directory must win: %s, %s", *database, *plugins)
	}

	if err := os.Remove(veerCLIDatabaseFile); err != nil {
		t.Fatal(err)
	}
	flags, database, plugins = parse()
	applyInstallStateDefaultsFrom(t.TempDir(), flags, database, plugins, io.Discard)
	if *database != veerCLIDatabaseFile {
		t.Fatalf("without an installed database the default stays relative: %s", *database)
	}
}

func TestInstallPluginsDirFollowsConfig(t *testing.T) {
	install := t.TempDir()
	if got := installPluginsDir(install); got != filepath.Join(install, defaultPluginsDir) {
		t.Fatalf("missing config: %s", got)
	}
	absolute := filepath.Join(t.TempDir(), "plugins")
	data, _ := json.Marshal(map[string]string{"plugins_dir": absolute})
	if err := os.WriteFile(filepath.Join(install, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := installPluginsDir(install); got != absolute {
		t.Fatalf("absolute plugins_dir: %s", got)
	}
}

// TestVeerMainHelper runs Main in a child process for the exit-code tests.
func TestVeerMainHelper(t *testing.T) {
	raw, ok := os.LookupEnv("VEER_TEST_MAIN_ARGS")
	if !ok {
		t.Skip("helper process")
	}
	os.Args = append([]string{"veer"}, strings.Fields(raw)...)
	Main("")
	os.Exit(0)
}

func TestVeerMainRejectsUnknownCommandsAndReportsCleanErrors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(args string) (int, string, string) {
		cmd := exec.Command(executable, "-test.run=^TestVeerMainHelper$")
		cmd.Env = append(os.Environ(), "VEER_TEST_MAIN_ARGS="+args)
		cmd.Dir = t.TempDir()
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, stdout.String(), stderr.String()
	}
	if code, _, stderr := run("kfunc status"); code != 2 || !strings.Contains(stderr, `unknown command "kfunc"`) || !strings.Contains(stderr, "veer kfuncs <command>") {
		t.Fatalf("typo must not start the daemon: code=%d stderr=%s", code, stderr)
	}
	if code, stdout, _ := run("help"); code != 0 || !strings.Contains(stdout, "veer kfuncs <command>") {
		t.Fatalf("help: code=%d stdout=%s", code, stdout)
	}
	code, _, stderr := run("kfuncs bogus")
	if code != 1 || !strings.Contains(stderr, `veer kfuncs: unknown kfuncs subcommand "bogus"`) {
		t.Fatalf("subcommand error: code=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stderr, "kfuncs command:") {
		t.Fatalf("errors must not use the log prefix: %s", stderr)
	}
}
