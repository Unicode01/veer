package app

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestReadSharedProxyHTTPHeadersAddsForwardedFor(t *testing.T) {
	input := "GET / HTTP/1.1\r\nHost: Example.com:443\r\nUser-Agent: test\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(input), sharedProxyHTTPReadBufferSize)

	headers, err := readSharedProxyHTTPHeaders(br, "203.0.113.10")
	if err != nil {
		t.Fatalf("readSharedProxyHTTPHeaders() error = %v", err)
	}
	if headers.host != "example.com" {
		t.Fatalf("readSharedProxyHTTPHeaders() host = %q, want example.com", headers.host)
	}
	if len(headers.lines) == 0 || headers.lines[len(headers.lines)-1] != "X-Forwarded-For: 203.0.113.10" {
		t.Fatalf("readSharedProxyHTTPHeaders() lines = %#v, want X-Forwarded-For appended", headers.lines)
	}
}

func TestReadSharedProxyHTTPHeadersRejectsOversizedLine(t *testing.T) {
	input := strings.Repeat("a", sharedProxyHTTPReadBufferSize+1) + "\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(input), sharedProxyHTTPReadBufferSize)

	if _, err := readSharedProxyHTTPHeaders(br, ""); err == nil {
		t.Fatal("readSharedProxyHTTPHeaders() error = nil, want oversized line failure")
	}
}

func TestPeekSharedProxyTLSRecord(t *testing.T) {
	payload := bytes.Repeat([]byte{0x01}, 5000)
	record := append([]byte{
		0x16,
		0x03, 0x03,
		byte(len(payload) >> 8),
		byte(len(payload)),
	}, payload...)
	br := bufio.NewReaderSize(bytes.NewReader(record), sharedProxyTLSReadBufferSize)

	got, err := peekSharedProxyTLSRecord(br)
	if err != nil {
		t.Fatalf("peekSharedProxyTLSRecord() error = %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Fatal("peekSharedProxyTLSRecord() returned unexpected record bytes")
	}
}

func TestPeekSharedProxyTLSRecordRejectsOversizedRecord(t *testing.T) {
	recordLen := sharedProxyMaxTLSRecordBytes + 1
	record := []byte{
		0x16,
		0x03, 0x03,
		byte(recordLen >> 8),
		byte(recordLen),
	}
	br := bufio.NewReaderSize(bytes.NewReader(record), sharedProxyTLSReadBufferSize)

	if _, err := peekSharedProxyTLSRecord(br); err == nil {
		t.Fatal("peekSharedProxyTLSRecord() error = nil, want oversized record failure")
	}
}
