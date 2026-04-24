//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var ebpfDeclaredSymbolPattern = regexp.MustCompile(`\b(bpf_[A-Za-z0-9_]+)\b`)
var ebpfUsedSymbolPattern = regexp.MustCompile(`\b(bpf_[A-Za-z0-9_]+)\s*\(`)

func validateEmbeddedEBPFHelperDeclarations(repoRoot string) error {
	ebpfDir := filepath.Join(repoRoot, "internal", "app", "ebpf")
	declared, err := collectEmbeddedEBPFDeclaredSymbols(filepath.Join(ebpfDir, "include"))
	if err != nil {
		return err
	}

	sourceFiles := []string{
		filepath.Join(ebpfDir, "forward-tc-bpf.c"),
		filepath.Join(ebpfDir, "forward-xdp-bpf.c"),
	}
	missing := make(map[string][]string)
	for _, sourcePath := range sourceFiles {
		used, err := collectEmbeddedEBPFUsedSymbols(sourcePath)
		if err != nil {
			return err
		}
		for symbol := range used {
			if _, ok := declared[symbol]; ok {
				continue
			}
			missing[symbol] = append(missing[symbol], filepath.Base(sourcePath))
		}
	}
	if len(missing) == 0 {
		return nil
	}

	items := make([]string, 0, len(missing))
	for symbol, files := range missing {
		sort.Strings(files)
		items = append(items, fmt.Sprintf("%s (%s)", symbol, strings.Join(files, ", ")))
	}
	sort.Strings(items)
	return fmt.Errorf("eBPF helper declarations are out of sync with source usage: missing %s in %s", strings.Join(items, "; "), filepath.Join(ebpfDir, "include"))
}

func collectEmbeddedEBPFDeclaredSymbols(path string) (map[string]struct{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	files := []string{path}
	if info.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.h"))
		if err != nil {
			return nil, fmt.Errorf("list eBPF include files in %s: %w", path, err)
		}
	}

	symbols := make(map[string]struct{})
	for _, current := range files {
		content, err := os.ReadFile(current)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", current, err)
		}
		cleaned := stripEmbeddedEBPFComments(string(content))
		for _, match := range ebpfDeclaredSymbolPattern.FindAllStringSubmatch(cleaned, -1) {
			if len(match) < 2 {
				continue
			}
			symbols[match[1]] = struct{}{}
		}
	}
	return symbols, nil
}

func collectEmbeddedEBPFUsedSymbols(path string) (map[string]struct{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	cleaned := stripEmbeddedEBPFComments(string(content))
	symbols := make(map[string]struct{})
	for _, match := range ebpfUsedSymbolPattern.FindAllStringSubmatch(cleaned, -1) {
		if len(match) < 2 {
			continue
		}
		symbols[match[1]] = struct{}{}
	}
	return symbols, nil
}

func stripEmbeddedEBPFComments(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		lines[i] = line
	}
	content = strings.Join(lines, "\n")

	for {
		start := strings.Index(content, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(content[start+2:], "*/")
		if end < 0 {
			content = content[:start]
			break
		}
		end += start + 2
		content = content[:start] + content[end+2:]
	}
	return content
}

func TestValidateEmbeddedEBPFHelperDeclarationsDetectsMissingHelper(t *testing.T) {
	repoRoot := t.TempDir()
	ebpfDir := filepath.Join(repoRoot, "internal", "app", "ebpf")
	includeDir := filepath.Join(ebpfDir, "include")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("create include dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(includeDir, "bpf_helpers.h"), []byte(`
static long (*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)0;
`), 0o644); err != nil {
		t.Fatalf("write helper header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(includeDir, "bpf_endian.h"), []byte(`
#define bpf_htons(x) (x)
`), 0o644); err != nil {
		t.Fatalf("write endian header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ebpfDir, "forward-tc-bpf.c"), []byte(`
int test(void) {
	return bpf_skb_change_head(0, 0, 0);
}
`), 0o644); err != nil {
		t.Fatalf("write tc source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ebpfDir, "forward-xdp-bpf.c"), []byte(`
int test(void) {
	return (int)(long)bpf_map_lookup_elem(0, 0);
}
`), 0o644); err != nil {
		t.Fatalf("write xdp source: %v", err)
	}

	err := validateEmbeddedEBPFHelperDeclarations(repoRoot)
	if err == nil {
		t.Fatal("validateEmbeddedEBPFHelperDeclarations() error = nil, want missing helper error")
	}
	if !strings.Contains(err.Error(), "bpf_skb_change_head") {
		t.Fatalf("validateEmbeddedEBPFHelperDeclarations() error = %q, want missing helper name", err.Error())
	}
	if !strings.Contains(err.Error(), "forward-tc-bpf.c") {
		t.Fatalf("validateEmbeddedEBPFHelperDeclarations() error = %q, want source file name", err.Error())
	}
}

func TestValidateEmbeddedEBPFHelperDeclarationsAllowsDeclaredHelpers(t *testing.T) {
	repoRoot := t.TempDir()
	ebpfDir := filepath.Join(repoRoot, "internal", "app", "ebpf")
	includeDir := filepath.Join(ebpfDir, "include")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("create include dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(includeDir, "bpf_helpers.h"), []byte(`
static long (*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)0;
static long (*const bpf_skb_change_head)(void *skb, unsigned int len, unsigned long long flags) = (void *)0;
`), 0o644); err != nil {
		t.Fatalf("write helper header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(includeDir, "bpf_endian.h"), []byte(`
#define bpf_htons(x) (x)
`), 0o644); err != nil {
		t.Fatalf("write endian header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ebpfDir, "forward-tc-bpf.c"), []byte(`
int test(void) {
	return bpf_skb_change_head(0, 0, 0);
}
`), 0o644); err != nil {
		t.Fatalf("write tc source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ebpfDir, "forward-xdp-bpf.c"), []byte(`
int test(void) {
	return (int)(long)bpf_map_lookup_elem(0, 0);
}
`), 0o644); err != nil {
		t.Fatalf("write xdp source: %v", err)
	}

	if err := validateEmbeddedEBPFHelperDeclarations(repoRoot); err != nil {
		t.Fatalf("validateEmbeddedEBPFHelperDeclarations() error = %v, want nil", err)
	}
}
