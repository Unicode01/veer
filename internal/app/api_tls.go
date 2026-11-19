package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The panel serves HTTPS when web_tls is on. Without web_tls_cert_file and
// web_tls_key_file it uses a self-signed certificate that it creates once
// under tls/ in its working directory (the install directory) and then keeps,
// so its fingerprint stays the same across restarts and upgrades and a client
// can pin it. It is replaced only when it has expired, cannot be read, or
// `veer tls regenerate` asks for it.
const (
	panelTLSDirName   = "tls"
	panelTLSCertName  = "panel.crt"
	panelTLSKeyName   = "panel.key"
	panelTLSValidity  = 10 * 365 * 24 * time.Hour
	panelTLSBackdate  = time.Hour
	panelTLSReloadGap = 30 * time.Second
)

type panelTLS struct {
	config      *tls.Config
	fingerprint string
	selfSigned  bool
	certPath    string
	// source serves a configured certificate; nil for the self-signed one,
	// which is config.Certificates[0].
	source *reloadingPanelCertificate
}

// coversHost reports whether the certificate the panel serves names host, a
// DNS name or an IP address.
func (p *panelTLS) coversHost(host string) bool {
	if p == nil || host == "" {
		return false
	}
	var cert *tls.Certificate
	if p.source != nil {
		cert = p.source.current()
	} else if p.config != nil && len(p.config.Certificates) > 0 {
		cert = &p.config.Certificates[0]
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}
		leaf = parsed
	}
	return leaf.VerifyHostname(host) == nil
}

// panelTLSPaths gives the files of the self-signed certificate under baseDir.
func panelTLSPaths(baseDir string) (string, string) {
	dir := filepath.Join(baseDir, panelTLSDirName)
	return filepath.Join(dir, panelTLSCertName), filepath.Join(dir, panelTLSKeyName)
}

// setupPanelTLS returns the TLS configuration of the panel: the configured
// certificate, or the self-signed one under baseDir.
func setupPanelTLS(cfg *Config, baseDir string) (*panelTLS, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg != nil && cfg.WebTLSCertFile != "" {
		certFile := resolvePanelTLSPath(baseDir, cfg.WebTLSCertFile)
		keyFile := resolvePanelTLSPath(baseDir, cfg.WebTLSKeyFile)
		source := &reloadingPanelCertificate{certFile: certFile, keyFile: keyFile, now: time.Now}
		cert, err := source.load()
		if err != nil {
			return nil, err
		}
		config.GetCertificate = source.get
		return &panelTLS{config: config, fingerprint: panelCertificateFingerprint(cert.Certificate[0]), certPath: certFile, source: source}, nil
	}
	certPath, keyPath := panelTLSPaths(baseDir)
	cert, created, err := loadOrCreateSelfSignedPanelCertificate(certPath, keyPath, panelCertificateNames(cfg), time.Now())
	if err != nil {
		return nil, err
	}
	fingerprint := panelCertificateFingerprint(cert.Certificate[0])
	if created {
		log.Printf("web TLS: created a self-signed certificate %s (sha256 %s)", certPath, fingerprint)
	}
	config.Certificates = []tls.Certificate{cert}
	return &panelTLS{config: config, fingerprint: fingerprint, selfSigned: true, certPath: certPath}, nil
}

func resolvePanelTLSPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// loadOrCreateSelfSignedPanelCertificate returns the stored certificate when
// it is valid at now, and otherwise writes a new one.
func loadOrCreateSelfSignedPanelCertificate(certPath, keyPath string, names panelCertificateNameSet, now time.Time) (tls.Certificate, bool, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr == nil && now.Before(leaf.NotAfter) && !now.Before(leaf.NotBefore) {
			cert.Leaf = leaf
			return cert, false, nil
		}
		if parseErr == nil {
			log.Printf("web TLS: self-signed certificate %s is outside its validity (%s to %s); creating a new one, so its fingerprint changes", certPath, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("web TLS: cannot use %s: %v; creating a new self-signed certificate, so its fingerprint changes", certPath, err)
	}
	cert, err = writeSelfSignedPanelCertificate(certPath, keyPath, names, now)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	return cert, true, nil
}

func writeSelfSignedPanelCertificate(certPath, keyPath string, names panelCertificateNameSet, now time.Time) (tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedPanelCertificate(names, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create %s: %w", filepath.Dir(certPath), err)
	}
	// Key first: a certificate on disk always has its key beside it.
	if err := writePanelTLSFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePanelTLSFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert, nil
}

func writePanelTLSFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// panelCertificateNameSet is what the self-signed certificate names: the
// addresses a browser may use for the panel when the certificate is created.
type panelCertificateNameSet struct {
	dns []string
	ips []net.IP
}

func panelCertificateNames(cfg *Config) panelCertificateNameSet {
	dnsSeen := map[string]bool{}
	ipSeen := map[string]bool{}
	var names panelCertificateNameSet
	addDNS := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || dnsSeen[name] || net.ParseIP(name) != nil {
			return
		}
		dnsSeen[name] = true
		names.dns = append(names.dns, name)
	}
	addIP := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if ipSeen[ip.String()] {
			return
		}
		ipSeen[ip.String()] = true
		names.ips = append(names.ips, ip)
	}
	addDNS("localhost")
	if hostname, err := os.Hostname(); err == nil {
		addDNS(hostname)
	}
	addIP(net.IPv4(127, 0, 0, 1))
	addIP(net.IPv6loopback)
	if cfg != nil {
		bind := normalizeWebBind(cfg.WebBind)
		if ip := net.ParseIP(bind); ip != nil {
			addIP(ip)
		} else {
			addDNS(bind)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if prefix, ok := addr.(*net.IPNet); ok {
				addIP(prefix.IP)
			}
		}
	}
	return names
}

func generateSelfSignedPanelCertificate(names panelCertificateNameSet, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	commonName := "Veer panel"
	if len(names.dns) > 1 {
		commonName += " " + names.dns[1]
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Veer"}},
		NotBefore:             now.Add(-panelTLSBackdate),
		NotAfter:              now.Add(panelTLSValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names.dns,
		IPAddresses:           names.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// panelCertificateFingerprint is the SHA-256 of the DER certificate in the
// colon-separated form browsers show.
func panelCertificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	var b strings.Builder
	for i, octet := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", octet)
	}
	return b.String()
}

// panelCertificateFileFingerprint reads the first certificate of a PEM file.
func panelCertificateFileFingerprint(path string) (string, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", nil, fmt.Errorf("%s holds no PEM certificate", path)
		}
		if block.Type == "CERTIFICATE" {
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", nil, fmt.Errorf("%s: %w", path, err)
			}
			return panelCertificateFingerprint(block.Bytes), leaf, nil
		}
	}
}

// reloadingPanelCertificate serves a configured certificate and picks up a
// renewed one (an ACME client replacing the files) without a restart.
type reloadingPanelCertificate struct {
	certFile string
	keyFile  string
	now      func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string
	checked time.Time
}

func (r *reloadingPanelCertificate) load() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *reloadingPanelCertificate) loadLocked() (*tls.Certificate, error) {
	stamp, err := panelTLSFileStamp(r.certFile, r.keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load web TLS certificate: %w", err)
	}
	r.cert, r.stamp, r.checked = &cert, stamp, r.now()
	return r.cert, nil
}

// current returns the certificate served last, without checking the files.
func (r *reloadingPanelCertificate) current() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert
}

func (r *reloadingPanelCertificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.cert != nil && now.Sub(r.checked) < panelTLSReloadGap {
		return r.cert, nil
	}
	r.checked = now
	stamp, err := panelTLSFileStamp(r.certFile, r.keyFile)
	if err != nil || stamp == r.stamp {
		return r.cert, nil
	}
	previous := r.cert
	if _, err := r.loadLocked(); err != nil {
		// A half-written renewal: keep serving the previous pair and try
		// again after the next gap.
		log.Printf("web TLS: reload %s: %v; keeping the previous certificate", r.certFile, err)
		r.cert = previous
		return previous, nil
	}
	log.Printf("web TLS: reloaded %s (sha256 %s)", r.certFile, panelCertificateFingerprint(r.cert.Certificate[0]))
	return r.cert, nil
}

func panelTLSFileStamp(paths ...string) (string, error) {
	var b bytes.Buffer
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("web TLS file: %w", err)
		}
		fmt.Fprintf(&b, "%s:%d:%d;", path, info.Size(), info.ModTime().UnixNano())
	}
	return b.String(), nil
}
