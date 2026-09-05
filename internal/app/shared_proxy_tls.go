package app

import (
	"bufio"
	"fmt"
)

// Assemble only the ClientHello for routing; leave the original records buffered
// so the backend receives the exact TLS wire stream, including fragmentation.
func peekSharedProxyClientHello(br *bufio.Reader) ([]byte, error) {
	hello := []byte{0x16, 3, 3, 0, 0}
	offset := 0
	for offset+5 <= sharedProxyTLSReadBufferSize {
		header, err := br.Peek(offset + 5)
		if err != nil {
			return nil, err
		}
		header = header[offset:]
		if header[0] != 0x16 || header[1] != 3 {
			return nil, fmt.Errorf("invalid TLS handshake record")
		}
		size := int(header[3])<<8 | int(header[4])
		if size == 0 || size > sharedProxyMaxTLSRecordBytes || offset+5+size > sharedProxyTLSReadBufferSize {
			return nil, fmt.Errorf("TLS ClientHello exceeds routing limit")
		}
		records, err := br.Peek(offset + 5 + size)
		if err != nil {
			return nil, err
		}
		hello = append(hello, records[offset+5:]...)
		offset += 5 + size
		if len(hello) < 9 {
			continue
		}
		if hello[5] != 1 {
			return nil, fmt.Errorf("expected TLS ClientHello")
		}
		length := int(hello[6])<<16 | int(hello[7])<<8 | int(hello[8])
		if length+9 > sharedProxyTLSReadBufferSize {
			return nil, fmt.Errorf("TLS ClientHello exceeds routing limit")
		}
		if len(hello) >= length+9 {
			hello = hello[:length+9]
			hello[3], hello[4] = byte((length+4)>>8), byte(length+4)
			return hello, nil
		}
	}
	return nil, fmt.Errorf("TLS ClientHello exceeds routing limit")
}
