package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func runTLSCLI(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "tls" {
		return false, nil
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) < 2 {
		writeTLSCLIUsage(stderr)
		return true, errors.New("tls subcommand is required")
	}
	switch args[1] {
	case "fingerprint":
		return true, runTLSFingerprintCLI(args[2:], stdout, stderr)
	case "regenerate":
		return true, runTLSRegenerateCLI(args[2:], stdout, stderr)
	case "help", "-h", "--help":
		writeTLSCLIUsage(stdout)
		return true, nil
	}
	writeTLSCLIUsage(stderr)
	return true, fmt.Errorf("unknown tls subcommand %q", args[1])
}

func writeTLSCLIUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  veer tls fingerprint [--json] [--install-dir DIR] [--config FILE]
  veer tls regenerate [--install-dir DIR] [--config FILE]

With web_tls on, the panel serves HTTPS with web_tls_cert_file, or with a
self-signed certificate it creates once under <install-dir>/tls/ and keeps.
fingerprint prints the SHA-256 fingerprint of the certificate the panel
serves, for checking the browser's warning or pinning it in a client.
regenerate replaces the self-signed certificate, for example after the host
got new addresses; restart the service to serve it. Clients that pinned the
old fingerprint need the new one.
`)
}

type tlsCLISettings struct {
	installDir string
	configPath string
	cfg        *Config
}

func loadTLSCLISettings(flags *flag.FlagSet, args []string, installDir, configPath *string) (tlsCLISettings, error) {
	if err := flags.Parse(args); err != nil {
		return tlsCLISettings{}, cliFlagError(err)
	}
	if flags.NArg() != 0 {
		return tlsCLISettings{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	_, dir, err := kernelHelperCLIInstallDir(*installDir)
	if err != nil {
		return tlsCLISettings{}, err
	}
	path := *configPath
	if path == "" {
		path = filepath.Join(dir, "config.json")
	}
	// Only the TLS settings matter here; the daemon validates the rest.
	data, err := os.ReadFile(path)
	if err != nil {
		return tlsCLISettings{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return tlsCLISettings{}, fmt.Errorf("%s: %w", path, err)
	}
	return tlsCLISettings{installDir: dir, configPath: path, cfg: &cfg}, nil
}

func runTLSFingerprintCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls fingerprint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	configPath := flags.String("config", "", "config of the daemon (default: <install-dir>/config.json)")
	settings, err := loadTLSCLISettings(flags, args, installDir, configPath)
	if err != nil {
		return err
	}
	certPath, _ := panelTLSPaths(settings.installDir)
	selfSigned := true
	if settings.cfg.WebTLSCertFile != "" {
		certPath = resolvePanelTLSPath(settings.installDir, settings.cfg.WebTLSCertFile)
		selfSigned = false
	}
	fingerprint, leaf, err := panelCertificateFileFingerprint(certPath)
	if errors.Is(err, os.ErrNotExist) && selfSigned {
		return fmt.Errorf("%s does not exist yet: the panel creates it when it starts with web_tls on", certPath)
	}
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{
			"web_tls":     settings.cfg.WebTLSEnabled(),
			"certificate": certPath,
			"self_signed": selfSigned,
			"sha256":      fingerprint,
			"not_after":   leaf.NotAfter.UTC().Format(time.RFC3339),
			"dns_names":   leaf.DNSNames,
			"ip_addresses": func() []string {
				out := make([]string, 0, len(leaf.IPAddresses))
				for _, ip := range leaf.IPAddresses {
					out = append(out, ip.String())
				}
				return out
			}(),
		})
	}
	fmt.Fprintln(stdout, fingerprint)
	if !settings.cfg.WebTLSEnabled() {
		fmt.Fprintf(stderr, "note: web_tls is off in %s, so the panel serves plain HTTP and not this certificate\n", settings.configPath)
	}
	return nil
}

func runTLSRegenerateCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tls regenerate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	configPath := flags.String("config", "", "config of the daemon (default: <install-dir>/config.json)")
	settings, err := loadTLSCLISettings(flags, args, installDir, configPath)
	if err != nil {
		return err
	}
	if settings.cfg.WebTLSCertFile != "" {
		return fmt.Errorf("%s sets web_tls_cert_file; replace that certificate instead", settings.configPath)
	}
	certPath, keyPath := panelTLSPaths(settings.installDir)
	cert, err := writeSelfSignedPanelCertificate(certPath, keyPath, panelCertificateNames(settings.cfg), time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, panelCertificateFingerprint(cert.Certificate[0]))
	fmt.Fprintf(stderr, "wrote %s; restart the service to serve it\n", certPath)
	return nil
}
