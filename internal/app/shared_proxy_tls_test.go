package app

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func TestSharedTLSClientHelloFragmentation(t *testing.T) {
	hello := buildSharedQUICTestClientHello("fragmented.example.test")
	for split := 1; split < len(hello); split++ {
		var wire []byte
		for _, data := range [][]byte{hello[:split], hello[split:]} {
			wire = append(wire, 0x16, 3, 3, byte(len(data)>>8), byte(len(data)))
			wire = append(wire, data...)
		}
		br := bufio.NewReaderSize(bytes.NewReader(wire), sharedProxyTLSReadBufferSize)
		record, err := peekSharedProxyClientHello(br)
		if err != nil || extractSNI(record) != "fragmented.example.test" {
			t.Fatalf("split %d: SNI=%q err=%v", split, extractSNI(record), err)
		}
		remaining, _ := io.ReadAll(br)
		if !bytes.Equal(remaining, wire) {
			t.Fatalf("split %d: TLS bytes consumed or changed", split)
		}
	}
}

func TestSharedTLSClientHelloRejectsIncompleteOrOversized(t *testing.T) {
	for _, wire := range [][]byte{
		{0x16, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff},
		{0x16, 3, 3, 0, 4, 1, 0, 0, 1},
		{0x16, 3, 3, 0, 0},
		{0x17, 3, 3, 0, 1, 0},
	} {
		br := bufio.NewReaderSize(bytes.NewReader(wire), sharedProxyTLSReadBufferSize)
		if _, err := peekSharedProxyClientHello(br); err == nil {
			t.Fatalf("accepted invalid hello %x", wire)
		}
	}
}
