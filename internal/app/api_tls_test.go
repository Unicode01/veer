package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const tlsTestToken = "0123456789abcdefghijklmnopqrstuv"

func writeTLSTestConfig(t *testing.T, dir string, extra map[string]any) string {
	t.Helper()
	cfg := map[string]any{"web_bind": "127.0.0.1", "web_port": 8080, "web_token": tlsTestToken}
	for key, value := range extra {
		cfg[key] = value
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWebTLSConfigDefaultsOffForConfigsWithoutIt(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(writeTLSTestConfig(t, dir, nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebTLSEnabled() {
		t.Fatal("a config without web_tls serves HTTPS; it must keep plain HTTP")
	}
	cfg, err = loadConfig(writeTLSTestConfig(t, dir, map[string]any{"web_tls": true}))
	if err != nil || !cfg.WebTLSEnabled() {
		t.Fatalf("web_tls true: enabled=%v err=%v", cfg != nil && cfg.WebTLSEnabled(), err)
	}
	if _, err := loadConfig(writeTLSTestConfig(t, dir, map[string]any{"web_tls": true, "web_tls_cert_file": "panel.pem"})); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Fatalf("cert without key: err = %v", err)
	}
}

func TestPanelSelfSignedCertificatePersists(t *testing.T) {
	dir := t.TempDir()
	enabled := true
	cfg := &Config{WebTLSSetting: &enabled}
	first, err := setupPanelTLS(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := setupPanelTLS(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.selfSigned || first.fingerprint == "" || first.fingerprint != second.fingerprint {
		t.Fatalf("fingerprints %q then %q, want one stable self-signed certificate", first.fingerprint, second.fingerprint)
	}
	certPath, keyPath := panelTLSPaths(dir)
	fingerprint, leaf, err := panelCertificateFileFingerprint(certPath)
	if err != nil || fingerprint != first.fingerprint {
		t.Fatalf("file fingerprint %q err %v, want %q", fingerprint, err, first.fingerprint)
	}
	names := strings.Join(leaf.DNSNames, ",")
	var ips []string
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	if !strings.Contains(names, "localhost") || !strings.Contains(strings.Join(ips, ","), "127.0.0.1") || !strings.Contains(strings.Join(ips, ","), "::1") {
		t.Fatalf("certificate names %v %v lack localhost or loopback", leaf.DNSNames, ips)
	}
	if leaf.NotAfter.Before(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Fatalf("certificate expires %s, want about ten years", leaf.NotAfter)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode = %v err %v, want 0600", info.Mode().Perm(), err)
		}
	}
}

func TestPanelSelfSignedCertificateReplacedWhenExpiredOrBroken(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := panelTLSPaths(dir)
	names := panelCertificateNames(nil)
	old, err := writeSelfSignedPanelCertificate(certPath, keyPath, names, time.Now().Add(-11*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, created, err := loadOrCreateSelfSignedPanelCertificate(certPath, keyPath, names, time.Now())
	if err != nil || !created || bytes.Equal(cert.Certificate[0], old.Certificate[0]) {
		t.Fatalf("expired certificate: created=%v err=%v, want a new one", created, err)
	}
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, created, err := loadOrCreateSelfSignedPanelCertificate(certPath, keyPath, names, time.Now()); err != nil || !created {
		t.Fatalf("broken certificate: created=%v err=%v, want a new one", created, err)
	}
	if _, created, err := loadOrCreateSelfSignedPanelCertificate(certPath, keyPath, names, time.Now()); err != nil || created {
		t.Fatalf("valid certificate: created=%v err=%v, want it kept", created, err)
	}
}

func TestPanelConfiguredCertificateReloads(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	first, err := writeSelfSignedPanelCertificate(certFile, keyFile, panelCertificateNames(nil), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	panel, err := setupPanelTLS(&Config{WebTLSSetting: &enabled, WebTLSCertFile: "fullchain.pem", WebTLSKeyFile: "privkey.pem"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if panel.selfSigned || panel.fingerprint != panelCertificateFingerprint(first.Certificate[0]) {
		t.Fatalf("configured certificate fingerprint %q, want the file's", panel.fingerprint)
	}

	now := time.Now()
	source := &reloadingPanelCertificate{certFile: certFile, keyFile: keyFile, now: func() time.Time { return now }}
	if _, err := source.load(); err != nil {
		t.Fatal(err)
	}
	renewed, err := writeSelfSignedPanelCertificate(certFile, keyFile, panelCertificateNames(nil), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := source.get(nil); !bytes.Equal(got.Certificate[0], first.Certificate[0]) {
		t.Fatal("reloaded before the gap")
	}
	now = now.Add(panelTLSReloadGap)
	if got, _ := source.get(nil); !bytes.Equal(got.Certificate[0], renewed.Certificate[0]) {
		t.Fatal("renewed certificate was not picked up")
	}
	if err := os.WriteFile(certFile, []byte("half written"), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(panelTLSReloadGap)
	if got, err := source.get(nil); err != nil || !bytes.Equal(got.Certificate[0], renewed.Certificate[0]) {
		t.Fatalf("broken renewal: err=%v, want the previous certificate kept", err)
	}
}

func TestAPIPlainRequestIsLocal(t *testing.T) {
	request := func(remote, local string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "http://panel/", nil)
		r.RemoteAddr = remote
		if local != "" {
			addr, _ := net.ResolveTCPAddr("tcp", local)
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, addr))
		}
		return r
	}
	for _, item := range []struct {
		remote, local string
		want          bool
	}{
		{"127.0.0.1:5000", "127.0.0.1:8080", true},
		{"[::1]:5000", "[::1]:8080", true},
		{"10.0.0.5:5000", "10.0.0.5:8080", true},
		{"[::ffff:10.0.0.5]:5000", "10.0.0.5:8080", true},
		{"10.0.0.6:5000", "10.0.0.5:8080", false},
		{"10.0.0.6:5000", "", false},
	} {
		if got := apiPlainRequestIsLocal(request(item.remote, item.local)); got != item.want {
			t.Errorf("remote %s local %s: local = %v, want %v", item.remote, item.local, got, item.want)
		}
	}
}

func TestServeAPIListenerSplitsProtocols(t *testing.T) {
	enabled := true
	panel, err := setupPanelTLS(&Config{WebTLSSetting: &enabled}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		_, _ = io.WriteString(w, scheme+" "+r.Method)
	})
	server := serveAPIListener(listener, handler, panel, func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	})
	defer server.Close()
	addr := listener.Addr().String()

	// A client that connects and says nothing holds up no one else.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	secure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}
	resp, err := secure.Get("https://" + addr + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "https GET" || resp.ProtoMajor != 2 {
		t.Fatalf("https: %s %q, want HTTP/2 and the handler", resp.Proto, body)
	}
	if got := panelCertificateFingerprint(resp.TLS.PeerCertificates[0].Raw); got != panel.fingerprint {
		t.Fatalf("served certificate %s, want %s", got, panel.fingerprint)
	}

	plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = plain.Get("http://" + addr + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "http GET" {
		t.Fatalf("plain HTTP from this host: %d %q, want it served", resp.StatusCode, body)
	}

	restore := apiPlainRequestIsLocal
	apiPlainRequestIsLocal = func(*http.Request) bool { return false }
	defer func() { apiPlainRequestIsLocal = restore }()
	resp, err = plain.Get("http://" + addr + "/app?tab=rules")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://"+addr+"/app?tab=rules" {
		t.Fatalf("remote plain GET: %d %q, want a redirect to https", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = plain.Post("http://"+addr+"/api/rules", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "HTTPS") || strings.Contains(string(body), "http POST") {
		t.Fatalf("remote plain POST: %d %q, want it refused", resp.StatusCode, body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("the panel port still accepts connections after shutdown")
	}
}

func TestTLSCLIFingerprintAndRegenerate(t *testing.T) {
	dir := t.TempDir()
	writeTLSTestConfig(t, dir, map[string]any{"web_tls": true})
	run := func(args ...string) (string, string, error) {
		var stdout, stderr bytes.Buffer
		handled, err := runTLSCLI(append(args, "--install-dir", dir), &stdout, &stderr)
		if !handled {
			t.Fatalf("%v not handled", args)
		}
		return strings.TrimSpace(stdout.String()), stderr.String(), err
	}
	if _, _, err := run("tls", "fingerprint"); err == nil || !strings.Contains(err.Error(), "does not exist yet") {
		t.Fatalf("fingerprint before the panel ran: %v", err)
	}
	created, _, err := run("tls", "regenerate")
	if err != nil || !strings.Contains(created, ":") {
		t.Fatalf("regenerate: %q %v", created, err)
	}
	got, _, err := run("tls", "fingerprint")
	if err != nil || got != created {
		t.Fatalf("fingerprint = %q %v, want %q", got, err, created)
	}
	enabled := true
	panel, err := setupPanelTLS(&Config{WebTLSSetting: &enabled}, dir)
	if err != nil || panel.fingerprint != created {
		t.Fatalf("panel serves %q %v, want the regenerated %q", panel.fingerprint, err, created)
	}
	out, _, err := run("tls", "fingerprint", "--json")
	var report struct {
		SHA256     string `json:"sha256"`
		SelfSigned bool   `json:"self_signed"`
		WebTLS     bool   `json:"web_tls"`
	}
	if err != nil || json.Unmarshal([]byte(out), &report) != nil || report.SHA256 != created || !report.SelfSigned || !report.WebTLS {
		t.Fatalf("fingerprint --json = %s %v", out, err)
	}

	writeTLSTestConfig(t, dir, map[string]any{"web_tls": true, "web_tls_cert_file": "tls/panel.crt", "web_tls_key_file": "tls/panel.key"})
	if _, _, err := run("tls", "regenerate"); err == nil || !strings.Contains(err.Error(), "web_tls_cert_file") {
		t.Fatalf("regenerate with a configured certificate: %v", err)
	}
	if _, err := x509.ParseCertificate(panelTLSMustReadDER(t, filepath.Join(dir, "tls", "panel.crt"))); err != nil {
		t.Fatal(err)
	}
}

func panelTLSMustReadDER(t *testing.T, path string) []byte {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(path, strings.TrimSuffix(path, ".crt")+".key")
	if err != nil {
		t.Fatal(err)
	}
	return cert.Certificate[0]
}
