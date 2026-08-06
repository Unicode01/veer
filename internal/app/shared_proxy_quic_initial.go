package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const (
	sharedQUICVersion1 uint32 = 0x00000001
	sharedQUICVersion2 uint32 = 0x6b3343cf

	sharedQUICMaxConnectionIDBytes = 20
	sharedQUICMaxCryptoBytes       = 64 * 1024
	sharedQUICMaxCryptoSegments    = 64
	sharedQUICMaxFrames            = 256
)

var (
	sharedQUICInitialSaltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	sharedQUICInitialSaltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

type sharedQUICPacketType uint8

const (
	sharedQUICPacketUnknown sharedQUICPacketType = iota
	sharedQUICPacketInitial
	sharedQUICPacketZeroRTT
	sharedQUICPacketHandshake
	sharedQUICPacketRetry
)

type sharedQUICLongHeader struct {
	version uint32
	typ     sharedQUICPacketType
	dcid    []byte
	scid    []byte
	off     int
}

func parseSharedQUICLongHeader(packet []byte) (sharedQUICLongHeader, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 {
		return sharedQUICLongHeader{}, errors.New("not a QUIC long-header packet")
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != 0 && packet[0]&0x40 == 0 {
		return sharedQUICLongHeader{}, errors.New("QUIC fixed bit is not set")
	}

	off := 5
	dcidLen := int(packet[off])
	off++
	if dcidLen > sharedQUICMaxConnectionIDBytes || off+dcidLen >= len(packet) {
		return sharedQUICLongHeader{}, errors.New("invalid QUIC destination connection ID")
	}
	dcid := append([]byte(nil), packet[off:off+dcidLen]...)
	off += dcidLen

	scidLen := int(packet[off])
	off++
	if scidLen > sharedQUICMaxConnectionIDBytes || off+scidLen > len(packet) {
		return sharedQUICLongHeader{}, errors.New("invalid QUIC source connection ID")
	}
	scid := append([]byte(nil), packet[off:off+scidLen]...)
	off += scidLen

	wireType := (packet[0] >> 4) & 0x03
	typ := sharedQUICPacketUnknown
	switch version {
	case sharedQUICVersion1:
		typ = [...]sharedQUICPacketType{
			sharedQUICPacketInitial,
			sharedQUICPacketZeroRTT,
			sharedQUICPacketHandshake,
			sharedQUICPacketRetry,
		}[wireType]
	case sharedQUICVersion2:
		typ = [...]sharedQUICPacketType{
			sharedQUICPacketRetry,
			sharedQUICPacketInitial,
			sharedQUICPacketZeroRTT,
			sharedQUICPacketHandshake,
		}[wireType]
	}

	return sharedQUICLongHeader{version: version, typ: typ, dcid: dcid, scid: scid, off: off}, nil
}

func parseSharedQUICVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, io.ErrUnexpectedEOF
	}
	value := uint64(data[0] & 0x3f)
	for i := 1; i < size; i++ {
		value = value<<8 | uint64(data[i])
	}
	return value, size, nil
}

type sharedQUICInitialKeys struct {
	key []byte
	iv  []byte
	hp  []byte
}

func deriveSharedQUICInitialKeys(version uint32, dcid []byte) (sharedQUICInitialKeys, error) {
	var salt []byte
	keyLabel := "quic key"
	ivLabel := "quic iv"
	hpLabel := "quic hp"
	switch version {
	case sharedQUICVersion1:
		salt = sharedQUICInitialSaltV1
	case sharedQUICVersion2:
		salt = sharedQUICInitialSaltV2
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	default:
		return sharedQUICInitialKeys{}, fmt.Errorf("unsupported QUIC version 0x%08x", version)
	}
	if len(dcid) == 0 {
		return sharedQUICInitialKeys{}, errors.New("empty QUIC destination connection ID")
	}

	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientSecret, err := expandSharedQUICLabel(initialSecret, "client in", sha256.Size)
	if err != nil {
		return sharedQUICInitialKeys{}, err
	}
	key, err := expandSharedQUICLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return sharedQUICInitialKeys{}, err
	}
	iv, err := expandSharedQUICLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return sharedQUICInitialKeys{}, err
	}
	hp, err := expandSharedQUICLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return sharedQUICInitialKeys{}, err
	}
	return sharedQUICInitialKeys{key: key, iv: iv, hp: hp}, nil
}

func expandSharedQUICLabel(secret []byte, label string, length int) ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(length))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte("tls13 "))
		child.AddBytes([]byte(label))
	})
	builder.AddUint8LengthPrefixed(func(*cryptobyte.Builder) {})
	info, err := builder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("build QUIC HKDF label: %w", err)
	}
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
		return nil, fmt.Errorf("expand QUIC HKDF label: %w", err)
	}
	return out, nil
}

func decodeSharedQUICPacketNumber(largest int64, truncated uint64, pnLen int) uint64 {
	expected := uint64(0)
	if largest >= 0 {
		expected = uint64(largest) + 1
	}
	window := uint64(1) << uint(pnLen*8)
	halfWindow := window / 2
	mask := window - 1
	candidate := (expected &^ mask) | truncated
	if candidate+halfWindow <= expected && candidate < (uint64(1)<<62)-window {
		return candidate + window
	}
	if candidate > expected+halfWindow && candidate >= window {
		return candidate - window
	}
	return candidate
}

func decryptSharedQUICInitial(packet []byte, largestPacketNumber int64) ([]byte, uint64, error) {
	header, err := parseSharedQUICLongHeader(packet)
	if err != nil {
		return nil, 0, err
	}
	if header.typ != sharedQUICPacketInitial {
		return nil, 0, errors.New("not a supported QUIC Initial packet")
	}
	keys, err := deriveSharedQUICInitialKeys(header.version, header.dcid)
	if err != nil {
		return nil, 0, err
	}

	off := header.off
	tokenLen, n, err := parseSharedQUICVarint(packet[off:])
	if err != nil {
		return nil, 0, fmt.Errorf("parse QUIC token length: %w", err)
	}
	off += n
	if tokenLen > uint64(len(packet)-off) {
		return nil, 0, errors.New("QUIC packet is truncated within token")
	}
	off += int(tokenLen)
	length, n, err := parseSharedQUICVarint(packet[off:])
	if err != nil {
		return nil, 0, fmt.Errorf("parse QUIC payload length: %w", err)
	}
	off += n
	pnOffset := off
	if length > uint64(len(packet)-pnOffset) {
		return nil, 0, errors.New("QUIC packet is truncated within protected payload")
	}
	packetEnd := pnOffset + int(length)
	const sampleSize = 16
	sampleOffset := pnOffset + 4
	if sampleOffset+sampleSize > packetEnd {
		return nil, 0, errors.New("QUIC Initial is too short for header protection")
	}

	hpBlock, err := aes.NewCipher(keys.hp)
	if err != nil {
		return nil, 0, fmt.Errorf("create QUIC header cipher: %w", err)
	}
	maskBytes := make([]byte, hpBlock.BlockSize())
	hpBlock.Encrypt(maskBytes, packet[sampleOffset:sampleOffset+sampleSize])
	unprotectedFirst := packet[0] ^ (maskBytes[0] & 0x0f)
	if unprotectedFirst&0x0c != 0 {
		return nil, 0, errors.New("QUIC Initial has non-zero reserved bits")
	}
	pnLen := int(unprotectedFirst&0x03) + 1
	if pnOffset+pnLen > packetEnd {
		return nil, 0, errors.New("QUIC packet number exceeds protected payload")
	}
	pnBytes := make([]byte, pnLen)
	truncatedPN := uint64(0)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = packet[pnOffset+i] ^ maskBytes[1+i]
		truncatedPN = truncatedPN<<8 | uint64(pnBytes[i])
	}
	packetNumber := decodeSharedQUICPacketNumber(largestPacketNumber, truncatedPN, pnLen)

	authenticatedHeader := append([]byte(nil), packet[:pnOffset+pnLen]...)
	authenticatedHeader[0] = unprotectedFirst
	copy(authenticatedHeader[pnOffset:], pnBytes)
	nonce := append([]byte(nil), keys.iv...)
	var encodedPN [8]byte
	binary.BigEndian.PutUint64(encodedPN[:], packetNumber)
	for i := range encodedPN {
		nonce[len(nonce)-len(encodedPN)+i] ^= encodedPN[i]
	}

	aeadBlock, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, 0, fmt.Errorf("create QUIC payload cipher: %w", err)
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return nil, 0, fmt.Errorf("create QUIC payload AEAD: %w", err)
	}
	ciphertext := packet[pnOffset+pnLen : packetEnd]
	if len(ciphertext) < aead.Overhead() {
		return nil, 0, errors.New("QUIC Initial ciphertext is too short")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, authenticatedHeader)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt QUIC Initial: %w", err)
	}
	return plaintext, packetNumber, nil
}

type sharedQUICCryptoSegment struct {
	offset uint64
	data   []byte
}

type sharedQUICFrameReader struct {
	data []byte
	err  error
}

func (reader *sharedQUICFrameReader) varint(name string) uint64 {
	if reader.err != nil {
		return 0
	}
	value, n, err := parseSharedQUICVarint(reader.data)
	if err != nil {
		reader.err = fmt.Errorf("parse QUIC %s: %w", name, err)
		return 0
	}
	reader.data = reader.data[n:]
	return value
}

func (reader *sharedQUICFrameReader) take(length uint64, name string) []byte {
	if reader.err != nil {
		return nil
	}
	if length > uint64(len(reader.data)) {
		reader.err = fmt.Errorf("QUIC %s is truncated", name)
		return nil
	}
	result := reader.data[:length]
	reader.data = reader.data[length:]
	return result
}

func parseSharedQUICInitialCrypto(packet []byte, largestPacketNumber int64) ([]sharedQUICCryptoSegment, uint64, error) {
	payload, packetNumber, err := decryptSharedQUICInitial(packet, largestPacketNumber)
	if err != nil {
		return nil, 0, err
	}
	reader := &sharedQUICFrameReader{data: payload}
	segments := make([]sharedQUICCryptoSegment, 0, 2)
	frameCount := 0
	for len(reader.data) > 0 {
		if reader.data[0] == 0 {
			reader.data = bytes.TrimLeft(reader.data, "\x00")
			continue
		}
		frameCount++
		if frameCount > sharedQUICMaxFrames {
			return nil, 0, errors.New("QUIC Initial contains too many frames")
		}
		typ := reader.varint("frame type")
		switch typ {
		case 0x01: // PING
		case 0x02, 0x03: // ACK and ACK_ECN
			reader.varint("ACK largest acknowledged")
			reader.varint("ACK delay")
			rangeCount := reader.varint("ACK range count")
			reader.varint("ACK first range")
			if rangeCount > sharedQUICMaxFrames {
				return nil, 0, errors.New("QUIC Initial ACK contains too many ranges")
			}
			for i := uint64(0); i < rangeCount; i++ {
				reader.varint("ACK gap")
				reader.varint("ACK range")
			}
			if typ == 0x03 {
				reader.varint("ACK ECT0")
				reader.varint("ACK ECT1")
				reader.varint("ACK ECN-CE")
			}
		case 0x06: // CRYPTO
			offset := reader.varint("CRYPTO offset")
			length := reader.varint("CRYPTO length")
			data := reader.take(length, "CRYPTO frame")
			if reader.err == nil {
				segments = append(segments, sharedQUICCryptoSegment{offset: offset, data: data})
			}
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			reader.varint("CONNECTION_CLOSE error code")
			if typ == 0x1c {
				reader.varint("CONNECTION_CLOSE frame type")
			}
			reasonLength := reader.varint("CONNECTION_CLOSE reason length")
			reader.take(reasonLength, "CONNECTION_CLOSE reason")
		default:
			return nil, 0, fmt.Errorf("unexpected frame type 0x%x in QUIC Initial", typ)
		}
		if reader.err != nil {
			return nil, 0, reader.err
		}
	}
	return segments, packetNumber, nil
}

func sharedQUICInitialPacketLength(packet []byte) (int, error) {
	header, err := parseSharedQUICLongHeader(packet)
	if err != nil {
		return 0, err
	}
	if header.typ != sharedQUICPacketInitial {
		return 0, errors.New("not a supported QUIC Initial packet")
	}
	off := header.off
	tokenLength, n, err := parseSharedQUICVarint(packet[off:])
	if err != nil {
		return 0, fmt.Errorf("parse QUIC token length: %w", err)
	}
	off += n
	if tokenLength > uint64(len(packet)-off) {
		return 0, errors.New("QUIC packet is truncated within token")
	}
	off += int(tokenLength)
	length, n, err := parseSharedQUICVarint(packet[off:])
	if err != nil {
		return 0, fmt.Errorf("parse QUIC payload length: %w", err)
	}
	off += n
	if length > uint64(len(packet)-off) {
		return 0, errors.New("QUIC packet is truncated within protected payload")
	}
	return off + int(length), nil
}

func parseSharedQUICInitialDatagramCrypto(datagram []byte, largestPacketNumber int64) ([]sharedQUICCryptoSegment, int64, error) {
	remaining := datagram
	segments := make([]sharedQUICCryptoSegment, 0, 2)
	processed := false
	for len(remaining) > 0 {
		packetLength, err := sharedQUICInitialPacketLength(remaining)
		if err != nil {
			if processed {
				break
			}
			return nil, largestPacketNumber, err
		}
		packetSegments, packetNumber, err := parseSharedQUICInitialCrypto(remaining[:packetLength], largestPacketNumber)
		if err != nil {
			return nil, largestPacketNumber, err
		}
		segments = append(segments, packetSegments...)
		if packetNumber <= uint64(^uint64(0)>>1) && int64(packetNumber) > largestPacketNumber {
			largestPacketNumber = int64(packetNumber)
		}
		processed = true
		remaining = remaining[packetLength:]
		if len(remaining) == 0 {
			break
		}
		nextHeader, err := parseSharedQUICLongHeader(remaining)
		if err != nil || nextHeader.typ != sharedQUICPacketInitial {
			break
		}
	}
	return segments, largestPacketNumber, nil
}

type sharedQUICCryptoAccumulator struct {
	segments            []sharedQUICCryptoSegment
	storedBytes         int
	largestPacketNumber int64
}

func newSharedQUICCryptoAccumulator() *sharedQUICCryptoAccumulator {
	return &sharedQUICCryptoAccumulator{largestPacketNumber: -1}
}

func (accumulator *sharedQUICCryptoAccumulator) feed(packet []byte) (string, bool, error) {
	segments, largestPacketNumber, err := parseSharedQUICInitialDatagramCrypto(packet, accumulator.largestPacketNumber)
	if err != nil {
		return "", false, err
	}
	for _, segment := range segments {
		if segment.offset > sharedQUICMaxCryptoBytes || uint64(len(segment.data)) > sharedQUICMaxCryptoBytes-segment.offset {
			return "", false, errors.New("QUIC ClientHello exceeds the reassembly limit")
		}
		for _, existing := range accumulator.segments {
			if sharedQUICCryptoSegmentsConflict(existing, segment) {
				return "", false, errors.New("QUIC ClientHello contains conflicting CRYPTO data")
			}
		}
	}
	for _, segment := range segments {
		duplicate := false
		for _, existing := range accumulator.segments {
			if existing.offset == segment.offset && bytes.Equal(existing.data, segment.data) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(accumulator.segments) >= sharedQUICMaxCryptoSegments || accumulator.storedBytes+len(segment.data) > sharedQUICMaxCryptoBytes {
			return "", false, errors.New("QUIC ClientHello has too many CRYPTO fragments")
		}
		accumulator.segments = append(accumulator.segments, sharedQUICCryptoSegment{
			offset: segment.offset,
			data:   append([]byte(nil), segment.data...),
		})
		accumulator.storedBytes += len(segment.data)
	}
	accumulator.largestPacketNumber = largestPacketNumber
	data := reassembleSharedQUICCrypto(accumulator.segments)
	if len(data) == 0 {
		return "", false, nil
	}
	return parseSharedQUICClientHelloSNI(data)
}

func sharedQUICCryptoSegmentsConflict(a, b sharedQUICCryptoSegment) bool {
	start := a.offset
	if b.offset > start {
		start = b.offset
	}
	aEnd := a.offset + uint64(len(a.data))
	bEnd := b.offset + uint64(len(b.data))
	end := aEnd
	if bEnd < end {
		end = bEnd
	}
	if start >= end {
		return false
	}
	return !bytes.Equal(
		a.data[start-a.offset:end-a.offset],
		b.data[start-b.offset:end-b.offset],
	)
}

func reassembleSharedQUICCrypto(segments []sharedQUICCryptoSegment) []byte {
	if len(segments) == 0 {
		return nil
	}
	sorted := append([]sharedQUICCryptoSegment(nil), segments...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].offset != sorted[j].offset {
			return sorted[i].offset < sorted[j].offset
		}
		return len(sorted[i].data) > len(sorted[j].data)
	})
	if sorted[0].offset != 0 {
		return nil
	}
	result := append([]byte(nil), sorted[0].data...)
	for _, segment := range sorted[1:] {
		next := uint64(len(result))
		if segment.offset > next {
			break
		}
		overlap := next - segment.offset
		if overlap < uint64(len(segment.data)) {
			result = append(result, segment.data[overlap:]...)
		}
	}
	return result
}

func parseSharedQUICClientHelloSNI(data []byte) (string, bool, error) {
	handshake := cryptobyte.String(data)
	var messageType uint8
	if !handshake.ReadUint8(&messageType) {
		return "", false, nil
	}
	if messageType != 1 {
		return "", false, fmt.Errorf("unexpected TLS handshake type %d in QUIC Initial", messageType)
	}
	var body cryptobyte.String
	if !handshake.ReadUint24LengthPrefixed(&body) {
		return "", false, nil
	}
	if !body.Skip(2 + 32) {
		return "", false, nil
	}
	var sessionID, cipherSuites, compressionMethods cryptobyte.String
	if !body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) ||
		!body.ReadUint8LengthPrefixed(&compressionMethods) {
		return "", false, nil
	}
	if body.Empty() {
		return "", false, errors.New("QUIC ClientHello does not contain extensions")
	}
	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) {
		return "", false, nil
	}
	for !extensions.Empty() {
		var extensionType uint16
		var extensionData cryptobyte.String
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return "", false, errors.New("malformed TLS extension in QUIC ClientHello")
		}
		if extensionType != 0 {
			continue
		}
		var names cryptobyte.String
		if !extensionData.ReadUint16LengthPrefixed(&names) {
			return "", false, errors.New("malformed server_name extension in QUIC ClientHello")
		}
		for !names.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
				return "", false, errors.New("malformed server name in QUIC ClientHello")
			}
			if nameType == 0 && len(name) > 0 {
				return string(name), true, nil
			}
		}
		return "", false, errors.New("QUIC ClientHello has no host_name server name")
	}
	return "", false, errors.New("QUIC ClientHello has no server_name extension")
}
