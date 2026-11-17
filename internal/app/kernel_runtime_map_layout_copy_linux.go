//go:build linux

package app

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"sort"

	"github.com/cilium/ebpf"
)

// kernelMapLayoutRule says how a hot restart may copy a preserved map whose
// value layout the successor's object grew.
type kernelMapLayoutRule struct {
	// prefixes are older value sizes that are a prefix of the current value
	// layout: later versions only appended fields, and every appended field
	// reads zero as unset.
	prefixes []uint32
	// banks are the successor's maps that hold entries under the same keys,
	// the copied map among them.
	banks []string
}

// kernelTCMapLayoutRules lists the tc maps a hot restart copies, filling the
// appended bytes with zeros, when the preserved map has an older value size,
// instead of falling back to fresh maps.
//
// When a preserved map's value grows again by appending fields, add its
// previous size to prefixes. When it changes in any other way, add nothing:
// the hot restart then goes cold, as it must.
var kernelTCMapLayoutRules = map[string]kernelMapLayoutRule{
	// d9041cb appended struct flow_fast_v4, the flow cache record, to the
	// 64-byte flow_value_v4. A zero stamp is never a current record.
	kernelFlowsMapName:        {prefixes: []uint32{64}, banks: []string{kernelFlowsMapName, kernelTCFlowsOldMapNameV4}},
	kernelTCFlowsOldMapNameV4: {prefixes: []uint32{64}, banks: []string{kernelFlowsMapName, kernelTCFlowsOldMapNameV4}},
}

// copies reports whether the rule lets a preserved map with the actual layout
// be copied into a map of the desired layout.
func (rule kernelMapLayoutRule) copies(actual, desired kernelHotRestartMapDescriptor) bool {
	if actual.ValueSize >= desired.ValueSize || !slices.Contains(rule.prefixes, actual.ValueSize) {
		return false
	}
	if kernelMapHasPerCPUValue(actual.Type) {
		return false
	}
	return actual.Type == desired.Type && actual.KeySize == desired.KeySize && actual.Flags == desired.Flags
}

// kernelMapLayoutCopy moves the entries of a preserved map whose value layout
// the successor's object grew into the successor's map of that role.
//
// The predecessor's programs keep running on the preserved map until the
// successor attaches its own, so the copy is made twice: once after the
// collection loads, so the successor's setup sees the flows, and once after
// attach, when the preserved map no longer changes. The second pass applies
// what the predecessor changed in between to every entry the successor's
// programs have not touched since the first.
type kernelMapLayoutCopy struct {
	// name is the successor's map the entries go into.
	name   string
	source *ebpf.Map
	// banks are the successor's maps holding entries under the same keys.
	banks []string
	// keySize, fromValueSize and toValueSize are the layouts the copy
	// converts between.
	keySize       uint32
	fromValueSize uint32
	toValueSize   uint32
	// copied maps each key the first pass wrote to the hash of the value it
	// wrote.
	copied map[string]uint64
}

// kernelMapLayoutCopyResult counts what one pass did.
type kernelMapLayoutCopyResult struct {
	Copied  int
	Added   int
	Updated int
	Deleted int
}

func newKernelMapLayoutCopy(name string, source *ebpf.Map, rule kernelMapLayoutRule, actual, desired kernelHotRestartMapDescriptor) *kernelMapLayoutCopy {
	return &kernelMapLayoutCopy{
		name:          name,
		source:        source,
		banks:         rule.banks,
		keySize:       actual.KeySize,
		fromValueSize: actual.ValueSize,
		toValueSize:   desired.ValueSize,
	}
}

func (c *kernelMapLayoutCopy) extend(value []byte) []byte {
	out := make([]byte, c.toValueSize)
	copy(out, value)
	return out
}

func kernelMapLayoutCopyHash(value []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(value)
	return h.Sum64()
}

// target returns the successor's map the entries go into.
func (c *kernelMapLayoutCopy) target(maps map[string]*ebpf.Map) (*ebpf.Map, error) {
	dst := maps[c.name]
	if dst == nil {
		return nil, fmt.Errorf("the new collection has no %s map", c.name)
	}
	if dst.KeySize() != c.keySize || dst.ValueSize() != c.toValueSize {
		return nil, fmt.Errorf("%s has key_size=%d value_size=%d, want %d and %d", c.name, dst.KeySize(), dst.ValueSize(), c.keySize, c.toValueSize)
	}
	return dst, nil
}

// copyInto writes every entry of the preserved map, zero-extended, into the
// successor's map. The predecessor may change the preserved map meanwhile;
// an iteration that keeps restarting is left to the second pass.
func (c *kernelMapLayoutCopy) copyInto(maps map[string]*ebpf.Map) (kernelMapLayoutCopyResult, error) {
	var result kernelMapLayoutCopyResult
	dst, err := c.target(maps)
	if err != nil {
		return result, err
	}
	c.copied = make(map[string]uint64)
	key := make([]byte, c.keySize)
	value := make([]byte, c.fromValueSize)
	iter := c.source.Iterate()
	for iter.Next(key, value) {
		extended := c.extend(value)
		if err := dst.Update(key, extended, ebpf.UpdateAny); err != nil {
			return result, fmt.Errorf("copy an entry into %s: %w", c.name, err)
		}
		c.copied[string(key)] = kernelMapLayoutCopyHash(extended)
	}
	result.Copied = len(c.copied)
	if err := iter.Err(); err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
		return result, fmt.Errorf("read the preserved entries for %s: %w", c.name, err)
	}
	return result, nil
}

// catchUp brings the successor's map up to date with the preserved map once
// the predecessor's programs are detached. A key the successor's programs
// created in any of the banks is theirs, and so is an entry they changed
// since the first pass.
func (c *kernelMapLayoutCopy) catchUp(maps map[string]*ebpf.Map) (kernelMapLayoutCopyResult, error) {
	var result kernelMapLayoutCopyResult
	dst, err := c.target(maps)
	if err != nil {
		return result, err
	}
	banks := make([]*ebpf.Map, 0, len(c.banks))
	for _, name := range c.banks {
		if m := maps[name]; m != nil {
			banks = append(banks, m)
		}
	}
	var errs []error
	seen := make(map[string]struct{}, len(c.copied))
	current := make([]byte, c.toValueSize)
	key := make([]byte, c.keySize)
	value := make([]byte, c.fromValueSize)
	iter := c.source.Iterate()
	for iter.Next(key, value) {
		seen[string(key)] = struct{}{}
		extended := c.extend(value)
		copiedHash, wasCopied := c.copied[string(key)]
		if !wasCopied {
			taken, err := kernelMapLayoutKeyInBanks(key, banks)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if taken {
				continue
			}
			err = dst.Update(key, extended, ebpf.UpdateNoExist)
			switch {
			case err == nil:
				result.Added++
			case errors.Is(err, ebpf.ErrKeyExist):
			default:
				errs = append(errs, fmt.Errorf("add an entry to %s: %w", c.name, err))
			}
			continue
		}
		if kernelMapLayoutCopyHash(extended) == copiedHash {
			continue
		}
		untouched, err := c.untouched(dst, key, copiedHash, current)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !untouched {
			continue
		}
		err = dst.Update(key, extended, ebpf.UpdateExist)
		switch {
		case err == nil:
			result.Updated++
		case errors.Is(err, ebpf.ErrKeyNotExist):
		default:
			errs = append(errs, fmt.Errorf("update an entry of %s: %w", c.name, err))
		}
	}
	if err := iter.Err(); err != nil {
		errs = append(errs, fmt.Errorf("read the preserved entries for %s: %w", c.name, err))
		return result, errors.Join(errs...)
	}

	// Entries the predecessor closed after the first pass.
	gone := make([]string, 0)
	for k := range c.copied {
		if _, ok := seen[k]; !ok {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		untouched, err := c.untouched(dst, []byte(k), c.copied[k], current)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !untouched {
			continue
		}
		if err := dst.Delete([]byte(k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("delete a closed entry from %s: %w", c.name, err))
			continue
		}
		result.Deleted++
	}
	return result, errors.Join(errs...)
}

// untouched reports whether dst still holds what the first pass wrote for key.
func (c *kernelMapLayoutCopy) untouched(dst *ebpf.Map, key []byte, copiedHash uint64, buf []byte) (bool, error) {
	err := dst.Lookup(key, buf)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read an entry of %s: %w", c.name, err)
	}
	return kernelMapLayoutCopyHash(buf) == copiedHash, nil
}

func kernelMapLayoutKeyInBanks(key []byte, banks []*ebpf.Map) (bool, error) {
	for _, bank := range banks {
		buf := make([]byte, bank.ValueSize())
		err := bank.Lookup(key, buf)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("look up a key in %s: %w", bank, err)
		}
	}
	return false, nil
}

func (c *kernelMapLayoutCopy) close() {
	if c == nil || c.source == nil {
		return
	}
	_ = c.source.Close()
	c.source = nil
}
