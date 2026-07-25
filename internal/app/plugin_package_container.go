package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	pluginPackageContainerArchiveName   = "package.tar.gz"
	pluginPackageContainerSignatureName = "signature.json"
	pluginPackageSignatureFileVersion   = 2
	pluginPackageMaxSignatureBytes      = 16 << 10
	pluginPackageMaxContainerBytes      = pluginPackageMaxArchiveBytes + pluginPackageMaxSignatureBytes + (4 << 10)
	pluginPackageMaxZIPOverheadBytes    = 4 << 10
)

type pluginPackageSignatureFile struct {
	Version       int    `json:"version"`
	SignerID      string `json:"signer_id"`
	PublicKey     string `json:"public_key"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Signature     string `json:"signature"`
	CreatedAt     string `json:"created_at"`
}

func isPluginPackageContainer(path string) (bool, error) {
	file, err := os.Open(path) // #nosec G304 -- path is caller-validated or manager-owned.
	if err != nil {
		return false, err
	}
	defer file.Close()
	var magic [2]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return false, fmt.Errorf("read plugin package header: %w", err)
	}
	return magic == [2]byte{'P', 'K'}, nil
}

func writePluginPackageContainer(archivePath, outputPath string, signature pluginPackageSignatureFile, force bool) (int64, error) {
	absArchive, _, archiveInfo, err := readPluginCLIRegularFile(archivePath, pluginPackageMaxArchiveBytes)
	if err != nil {
		return 0, err
	}
	absOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return 0, err
	}
	if absArchive == absOutput {
		return 0, fmt.Errorf("signed plugin package output must differ from its input archive")
	}
	if err := validatePluginPackageSignatureFile(signature); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(absOutput), 0o750); err != nil {
		return 0, err
	}
	temp, err := os.CreateTemp(filepath.Dir(absOutput), ".veer-plugin-signed-*")
	if err != nil {
		return 0, err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	zipWriter := zip.NewWriter(temp)
	payloadHeader := &zip.FileHeader{Name: pluginPackageContainerArchiveName, Method: zip.Store}
	payloadHeader.SetMode(0o644)
	payloadWriter, err := zipWriter.CreateHeader(payloadHeader)
	if err != nil {
		return 0, err
	}
	archive, err := os.Open(absArchive) // #nosec G304 -- archive was validated as a bounded regular file.
	if err != nil {
		return 0, err
	}
	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(payloadWriter, hash), archive, archiveInfo.Size())
	var extra [1]byte
	extraRead, extraErr := archive.Read(extra[:])
	closeArchiveErr := archive.Close()
	if copyErr != nil || written != archiveInfo.Size() || extraRead != 0 || (extraErr != nil && extraErr != io.EOF) || closeArchiveErr != nil {
		return 0, fmt.Errorf("plugin package archive changed while signing")
	}
	if hex.EncodeToString(hash.Sum(nil)) != signature.ArchiveSHA256 {
		return 0, fmt.Errorf("plugin package archive changed while signing")
	}
	signatureData, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		return 0, err
	}
	signatureData = append(signatureData, '\n')
	if len(signatureData) > pluginPackageMaxSignatureBytes {
		return 0, fmt.Errorf("plugin package signature metadata exceeds %d bytes", pluginPackageMaxSignatureBytes)
	}
	signatureHeader := &zip.FileHeader{Name: pluginPackageContainerSignatureName, Method: zip.Store}
	signatureHeader.SetMode(0o644)
	signatureWriter, err := zipWriter.CreateHeader(signatureHeader)
	if err != nil {
		return 0, err
	}
	if _, err := signatureWriter.Write(signatureData); err != nil {
		return 0, err
	}
	if err := zipWriter.Close(); err != nil {
		return 0, err
	}
	if err := temp.Sync(); err != nil {
		return 0, err
	}
	if err := temp.Close(); err != nil {
		return 0, err
	}
	containerInfo, err := os.Stat(tempPath)
	if err != nil {
		return 0, err
	}
	if containerInfo.Size() <= 0 || containerInfo.Size() > pluginPackageMaxContainerBytes {
		return 0, fmt.Errorf("signed plugin package exceeds %d bytes", pluginPackageMaxContainerBytes)
	}
	if existing, err := os.Lstat(absOutput); err == nil {
		if !force || existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return 0, fmt.Errorf("signed plugin package output already exists")
		}
		if err := os.Remove(absOutput); err != nil {
			return 0, err
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	if err := os.Rename(tempPath, absOutput); err != nil {
		return 0, err
	}
	cleanup = false
	return containerInfo.Size(), nil
}

func extractPluginPackageContainer(containerPath, archivePath string) (string, pluginPackageSignature, error) {
	container, err := os.Open(containerPath) // #nosec G304 -- containerPath is caller-validated or manager-owned.
	if err != nil {
		return "", pluginPackageSignature{}, err
	}
	defer container.Close()
	info, err := container.Stat()
	if err != nil {
		return "", pluginPackageSignature{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > pluginPackageMaxContainerBytes {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package must be a non-empty regular file no larger than %d bytes", pluginPackageMaxContainerBytes)
	}
	if err := validatePluginPackageZIPDirectory(container, info.Size()); err != nil {
		return "", pluginPackageSignature{}, err
	}
	reader, err := zip.NewReader(container, info.Size())
	if err != nil {
		return "", pluginPackageSignature{}, fmt.Errorf("open signed plugin package: %w", err)
	}
	if reader.Comment != "" || len(reader.File) != 2 {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package must contain exactly %s and %s", pluginPackageContainerArchiveName, pluginPackageContainerSignatureName)
	}
	entries := make(map[string]*zip.File, 2)
	for _, entry := range reader.File {
		if entry == nil || (entry.Name != pluginPackageContainerArchiveName && entry.Name != pluginPackageContainerSignatureName) {
			return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package contains an unexpected entry")
		}
		if _, duplicate := entries[entry.Name]; duplicate {
			return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package contains duplicate entry %q", entry.Name)
		}
		if entry.Flags&0x1 != 0 || entry.Method != zip.Store || entry.FileInfo().IsDir() || !entry.FileInfo().Mode().IsRegular() || len(entry.Extra) != 0 || entry.Comment != "" {
			return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package entry %q uses unsupported ZIP metadata", entry.Name)
		}
		if entry.CompressedSize64 != entry.UncompressedSize64 {
			return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package entry %q must not be compressed", entry.Name)
		}
		entries[entry.Name] = entry
	}
	payload := entries[pluginPackageContainerArchiveName]
	metadataEntry := entries[pluginPackageContainerSignatureName]
	if payload == nil || metadataEntry == nil {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package is missing required entries")
	}
	if payload.UncompressedSize64 == 0 || payload.UncompressedSize64 > pluginPackageMaxArchiveBytes {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package payload exceeds %d bytes", pluginPackageMaxArchiveBytes)
	}
	if metadataEntry.UncompressedSize64 == 0 || metadataEntry.UncompressedSize64 > pluginPackageMaxSignatureBytes {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package signature metadata exceeds %d bytes", pluginPackageMaxSignatureBytes)
	}
	entryBytes := payload.CompressedSize64 + metadataEntry.CompressedSize64
	containerBytes := uint64(info.Size()) // #nosec G115 -- size is positive and bounded to pluginPackageMaxContainerBytes above.
	if entryBytes > containerBytes || containerBytes-entryBytes > pluginPackageMaxZIPOverheadBytes {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package contains unexpected ZIP padding")
	}
	metadataData, err := readPluginPackageContainerEntry(metadataEntry, pluginPackageMaxSignatureBytes)
	if err != nil {
		return "", pluginPackageSignature{}, fmt.Errorf("read signed plugin package metadata: %w", err)
	}
	var metadata pluginPackageSignatureFile
	if err := decodePluginPackageSignatureFile(metadataData, &metadata); err != nil {
		return "", pluginPackageSignature{}, err
	}

	payloadReader, err := payload.Open()
	if err != nil {
		return "", pluginPackageSignature{}, err
	}
	archive, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- archivePath is a private manager staging or CLI verification path.
	if err != nil {
		_ = payloadReader.Close()
		return "", pluginPackageSignature{}, err
	}
	keepArchive := false
	defer func() {
		_ = archive.Close()
		_ = payloadReader.Close()
		if !keepArchive {
			_ = os.Remove(archivePath)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(payloadReader, pluginPackageMaxArchiveBytes+1))
	closePayloadErr := payloadReader.Close()
	closeArchiveErr := archive.Close()
	if copyErr != nil {
		return "", pluginPackageSignature{}, copyErr
	}
	if closePayloadErr != nil {
		return "", pluginPackageSignature{}, closePayloadErr
	}
	if closeArchiveErr != nil {
		return "", pluginPackageSignature{}, closeArchiveErr
	}
	if written != int64(payload.UncompressedSize64) || written > pluginPackageMaxArchiveBytes {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package payload size changed while reading")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != metadata.ArchiveSHA256 {
		return "", pluginPackageSignature{}, fmt.Errorf("signed plugin package payload digest does not match signature metadata")
	}
	keepArchive = true
	return digest, pluginPackageSignature{
		SignerID: metadata.SignerID, PublicKey: metadata.PublicKey, Signature: metadata.Signature,
	}, nil
}

func validatePluginPackageZIPDirectory(file *os.File, size int64) error {
	const endRecordBytes = 22
	if size < endRecordBytes {
		return fmt.Errorf("signed plugin package ZIP directory is invalid")
	}
	record := make([]byte, endRecordBytes)
	if _, err := file.ReadAt(record, size-endRecordBytes); err != nil {
		return fmt.Errorf("read signed plugin package ZIP directory: %w", err)
	}
	if binary.LittleEndian.Uint32(record[0:4]) != 0x06054b50 ||
		binary.LittleEndian.Uint16(record[4:6]) != 0 ||
		binary.LittleEndian.Uint16(record[6:8]) != 0 ||
		binary.LittleEndian.Uint16(record[8:10]) != 2 ||
		binary.LittleEndian.Uint16(record[10:12]) != 2 ||
		binary.LittleEndian.Uint16(record[20:22]) != 0 {
		return fmt.Errorf("signed plugin package ZIP directory must declare exactly two entries without comments or multiple disks")
	}
	directoryBytes := int64(binary.LittleEndian.Uint32(record[12:16]))
	directoryOffset := int64(binary.LittleEndian.Uint32(record[16:20]))
	if directoryBytes <= 0 || directoryBytes > pluginPackageMaxZIPOverheadBytes || directoryOffset < 0 || directoryOffset+directoryBytes != size-endRecordBytes {
		return fmt.Errorf("signed plugin package ZIP directory bounds are invalid")
	}
	return nil
}

func readPluginPackageContainerEntry(entry *zip.File, maxBytes int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	dataBytes := uint64(len(data))                                             // #nosec G115 -- len is non-negative and the read is bounded by maxBytes above.
	if dataBytes != entry.UncompressedSize64 || dataBytes > uint64(maxBytes) { // #nosec G115 -- maxBytes is a positive 16 KiB package limit.
		return nil, fmt.Errorf("entry size changed while reading")
	}
	return data, nil
}

func decodePluginPackageSignatureFile(data []byte, target *pluginPackageSignatureFile) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode signed plugin package metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("signed plugin package metadata contains trailing JSON")
	}
	return validatePluginPackageSignatureFile(*target)
}

func validatePluginPackageSignatureFile(value pluginPackageSignatureFile) error {
	if value.Version != pluginPackageSignatureFileVersion {
		return fmt.Errorf("signed plugin package metadata version is unsupported")
	}
	if len(value.SignerID) != 32 || strings.ToLower(value.SignerID) != value.SignerID {
		return fmt.Errorf("signed plugin package signer id is invalid")
	}
	if _, err := hex.DecodeString(value.SignerID); err != nil {
		return fmt.Errorf("signed plugin package signer id is invalid")
	}
	if len(value.ArchiveSHA256) != sha256.Size*2 || strings.ToLower(value.ArchiveSHA256) != value.ArchiveSHA256 {
		return fmt.Errorf("signed plugin package archive digest is invalid")
	}
	if _, err := hex.DecodeString(value.ArchiveSHA256); err != nil {
		return fmt.Errorf("signed plugin package archive digest is invalid")
	}
	publicKey, err := decodePluginTrustPublicKey(value.PublicKey)
	if err != nil || pluginTrustKeyID(publicKey) != value.SignerID {
		return fmt.Errorf("signed plugin package signer identity is invalid")
	}
	if _, err := decodePluginPackageSignature(value.Signature); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, value.CreatedAt); err != nil {
		return fmt.Errorf("signed plugin package creation time is invalid")
	}
	return nil
}
