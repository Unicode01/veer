package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/quic"
)

func TestSharedQUICInitialKeysMatchRFCVectors(t *testing.T) {
	dcid, err := hex.DecodeString("8394c8f03e515708")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		version uint32
		key     string
		iv      string
		hp      string
	}{
		{
			name:    "v1",
			version: sharedQUICVersion1,
			key:     "1f369613dd76d5467730efcbe3b1a22d",
			iv:      "fa044b2f42a3fd3b46fb255c",
			hp:      "9f50449e04a0e810283a1e9933adedd2",
		},
		{
			name:    "v2",
			version: sharedQUICVersion2,
			key:     "8b1a0bc121284290a29e0971b5cd045d",
			iv:      "91f73e2351d8fa91660e909f",
			hp:      "45b95e15235d6f45a6b19cbcb0294ba9",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys, err := deriveSharedQUICInitialKeys(test.version, dcid)
			if err != nil {
				t.Fatalf("deriveSharedQUICInitialKeys() error = %v", err)
			}
			if got := hex.EncodeToString(keys.key); got != test.key {
				t.Fatalf("key = %s, want %s", got, test.key)
			}
			if got := hex.EncodeToString(keys.iv); got != test.iv {
				t.Fatalf("iv = %s, want %s", got, test.iv)
			}
			if got := hex.EncodeToString(keys.hp); got != test.hp {
				t.Fatalf("hp = %s, want %s", got, test.hp)
			}
		})
	}
}

func TestSharedQUICInitialReassemblesFragmentedClientHello(t *testing.T) {
	hello := buildSharedQUICTestClientHello("fragmented.example.test")
	dcid := []byte("12345678")
	split := len(hello) / 2
	second := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 1, uint64(split), hello[split:])
	first := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 0, 0, hello[:split])

	accumulator := newSharedQUICCryptoAccumulator()
	if domain, complete, err := accumulator.feed(second); err != nil || complete || domain != "" {
		t.Fatalf("feed(second) = (%q, %v, %v), want incomplete", domain, complete, err)
	}
	domain, complete, err := accumulator.feed(first)
	if err != nil {
		t.Fatalf("feed(first) error = %v", err)
	}
	if !complete || domain != "fragmented.example.test" {
		t.Fatalf("feed(first) = (%q, %v), want fragmented.example.test", domain, complete)
	}
}

func TestSharedQUICInitialReassemblesCoalescedClientHello(t *testing.T) {
	hello := buildSharedQUICTestClientHello("coalesced.example.test")
	dcid := []byte("12345678")
	split := len(hello) / 2
	first := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 0, 0, hello[:split])
	second := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 1, uint64(split), hello[split:])
	datagram := append(append([]byte(nil), first...), second...)

	domain, complete, err := newSharedQUICCryptoAccumulator().feed(datagram)
	if err != nil {
		t.Fatalf("feed() error = %v", err)
	}
	if !complete || domain != "coalesced.example.test" {
		t.Fatalf("feed() = (%q, %v), want coalesced.example.test", domain, complete)
	}
}

func TestSharedQUICInitialSupportsVersion2(t *testing.T) {
	hello := buildSharedQUICTestClientHello("v2.example.test")
	packet := buildSharedQUICTestInitial(t, sharedQUICVersion2, []byte("abcdefgh"), 7, 0, hello)
	domain, complete, err := newSharedQUICCryptoAccumulator().feed(packet)
	if err != nil {
		t.Fatalf("feed() error = %v", err)
	}
	if !complete || domain != "v2.example.test" {
		t.Fatalf("feed() = (%q, %v), want v2.example.test", domain, complete)
	}
}

func TestSharedQUICInitialRejectsConflictingCrypto(t *testing.T) {
	hello := buildSharedQUICTestClientHello("conflict.example.test")
	dcid := []byte("12345678")
	first := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 0, 0, hello[:24])
	overlap := append([]byte(nil), hello[12:36]...)
	overlap[0] ^= 0xff
	second := buildSharedQUICTestInitial(t, sharedQUICVersion1, dcid, 1, 12, overlap)

	accumulator := newSharedQUICCryptoAccumulator()
	if _, _, err := accumulator.feed(first); err != nil {
		t.Fatalf("feed(first) error = %v", err)
	}
	if _, _, err := accumulator.feed(second); err == nil {
		t.Fatal("feed(second) error = nil, want conflicting CRYPTO failure")
	}
}

func TestSharedQUICInitialEnforcesCryptoLimit(t *testing.T) {
	packet := buildSharedQUICTestInitial(t, sharedQUICVersion1, []byte("12345678"), 0, sharedQUICMaxCryptoBytes, []byte{1})
	if _, _, err := newSharedQUICCryptoAccumulator().feed(packet); err == nil {
		t.Fatal("feed() error = nil, want reassembly limit failure")
	}
}

func TestSharedQUICSessionMatchesGreasedShortHeaderAndCapsCIDs(t *testing.T) {
	endpointKey := "client"
	cid := []byte("server01")
	session := &sharedQUICSession{
		endpointKey: endpointKey,
		aliases:     map[string]struct{}{},
	}
	relay := &sharedQUICRelay{
		sessions:           map[*sharedQUICSession]struct{}{session: {}},
		sessionsByAlias:    map[string]*sharedQUICSession{},
		sessionsByEndpoint: map[string]map[*sharedQUICSession]struct{}{endpointKey: {session: {}}},
	}
	relay.addSessionCID(session, cid)
	packet := append([]byte{0x00}, cid...)
	packet = append(packet, 0xaa)
	if got := relay.findSession(endpointKey, packet); got != session {
		t.Fatalf("findSession() = %p, want %p", got, session)
	}
	for i := 0; i < sharedQUICMaxSessionCIDs+10; i++ {
		relay.addSessionCID(session, []byte{byte(i + 1)})
	}
	if got := len(session.aliases); got != sharedQUICMaxSessionCIDs {
		t.Fatalf("session CID count = %d, want %d", got, sharedQUICMaxSessionCIDs)
	}
}

func TestSharedQUICProxyEndToEndWithRetry(t *testing.T) {
	serverTLS, clientTLS := sharedQUICTestTLSConfigs(t, "quic.example.test")
	backend, err := quic.Listen("udp4", "127.0.0.1:0", &quic.Config{
		TLSConfig:                serverTLS,
		RequireAddressValidation: true,
	})
	if err != nil {
		t.Fatalf("quic.Listen() error = %v", err)
	}
	defer backend.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := backend.Accept(ctx)
		if err != nil {
			serverResult <- fmt.Errorf("accept connection: %w", err)
			return
		}
		defer conn.Close()
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverResult <- fmt.Errorf("accept stream: %w", err)
			return
		}
		request := make([]byte, 4)
		if _, err := io.ReadFull(stream, request); err != nil {
			serverResult <- fmt.Errorf("read request: %w", err)
			return
		}
		if !bytes.Equal(request, []byte("ping")) {
			serverResult <- fmt.Errorf("request = %q, want ping", request)
			return
		}
		if _, err := stream.Write([]byte("pong")); err != nil {
			serverResult <- fmt.Errorf("write response: %w", err)
			return
		}
		stream.CloseWrite()
		serverResult <- nil
	}()

	proxyConn, err := listenSharedProxyQUIC(ctx, "", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenSharedProxyQUIC() error = %v", err)
	}
	stats := &siteStats{}
	proxy := &sharedProxyEngine{
		quicRoutes:        map[string]string{"quic.example.test": backend.LocalAddr().String()},
		domainStats:       map[string]*siteStats{"quic.example.test": stats},
		domainSourceIP:    map[string]string{"quic.example.test": ""},
		domainTransparent: map[string]bool{"quic.example.test": false},
	}
	proxyCtx, stopProxy := context.WithCancel(ctx)
	proxyDone := make(chan struct{})
	go func() {
		proxy.serveQUIC(proxyCtx, proxyConn, proxyConn.LocalAddr().String())
		close(proxyDone)
	}()
	defer func() {
		stopProxy()
		proxyConn.Close()
		select {
		case <-proxyDone:
		case <-time.After(2 * time.Second):
			t.Error("QUIC proxy did not stop")
		}
	}()

	clientEndpoint, err := quic.Listen("udp4", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("client quic.Listen() error = %v", err)
	}
	defer clientEndpoint.Close(context.Background())
	clientConn, err := clientEndpoint.Dial(ctx, "udp4", proxyConn.LocalAddr().String(), &quic.Config{TLSConfig: clientTLS})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer clientConn.Close()
	stream, err := clientConn.NewStream(ctx)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	stream.CloseWrite()
	response := make([]byte, 4)
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if !bytes.Equal(response, []byte("pong")) {
		t.Fatalf("response = %q, want pong", response)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&stats.totalConns) != 1 {
		t.Fatalf("total connections = %d, want 1", atomic.LoadInt64(&stats.totalConns))
	}
	if atomic.LoadInt64(&stats.bytesIn) == 0 || atomic.LoadInt64(&stats.bytesOut) == 0 {
		t.Fatalf("traffic stats = in:%d out:%d, want both non-zero", atomic.LoadInt64(&stats.bytesIn), atomic.LoadInt64(&stats.bytesOut))
	}
}

func buildSharedQUICTestClientHello(domain string) []byte {
	name := []byte(domain)
	serverNames := make([]byte, 0, len(name)+5)
	serverNames = binary.BigEndian.AppendUint16(serverNames, uint16(len(name)+3))
	serverNames = append(serverNames, 0)
	serverNames = binary.BigEndian.AppendUint16(serverNames, uint16(len(name)))
	serverNames = append(serverNames, name...)
	extensions := make([]byte, 0, len(serverNames)+4)
	extensions = binary.BigEndian.AppendUint16(extensions, 0)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(serverNames)))
	extensions = append(extensions, serverNames...)

	body := make([]byte, 0, len(extensions)+48)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

func buildSharedQUICTestInitial(t *testing.T, version uint32, dcid []byte, packetNumber uint64, cryptoOffset uint64, cryptoData []byte) []byte {
	t.Helper()
	keys, err := deriveSharedQUICInitialKeys(version, dcid)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	plaintext := appendSharedQUICTestVarint(nil, 0x06)
	plaintext = appendSharedQUICTestVarint(plaintext, cryptoOffset)
	plaintext = appendSharedQUICTestVarint(plaintext, uint64(len(cryptoData)))
	plaintext = append(plaintext, cryptoData...)
	plaintext = append(plaintext, make([]byte, 32)...)

	const packetNumberLength = 2
	first := byte(0xc0 | byte(packetNumberLength-1))
	if version == sharedQUICVersion2 {
		first |= 0x10
	}
	header := []byte{first}
	header = binary.BigEndian.AppendUint32(header, version)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0)
	header = appendSharedQUICTestVarint(header, 0)
	header = appendSharedQUICTestVarint(header, uint64(packetNumberLength+len(plaintext)+16))
	pnOffset := len(header)
	pn := []byte{byte(packetNumber >> 8), byte(packetNumber)}
	aad := append(append([]byte(nil), header...), pn...)

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		t.Fatalf("AES key: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM: %v", err)
	}
	nonce := append([]byte(nil), keys.iv...)
	var encodedPN [8]byte
	binary.BigEndian.PutUint64(encodedPN[:], packetNumber)
	for i := range encodedPN {
		nonce[len(nonce)-len(encodedPN)+i] ^= encodedPN[i]
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	packet := append(aad, ciphertext...)

	hpBlock, err := aes.NewCipher(keys.hp)
	if err != nil {
		t.Fatalf("AES header protection key: %v", err)
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < packetNumberLength; i++ {
		packet[pnOffset+i] ^= mask[i+1]
	}
	return packet
}

func appendSharedQUICTestVarint(dst []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(dst, byte(value))
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(dst, uint16(value)|(1<<14))
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(value)|(2<<30))
	default:
		return binary.BigEndian.AppendUint64(dst, value|(uint64(3)<<62))
	}
}

func sharedQUICTestTLSConfigs(t *testing.T, domain string) (*tls.Config, *tls.Config) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	const protocol = "veer-quic-test"
	server := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{protocol}, MinVersion: tls.VersionTLS13}
	client := &tls.Config{RootCAs: roots, ServerName: domain, NextProtos: []string{protocol}, MinVersion: tls.VersionTLS13}
	return server, client
}
