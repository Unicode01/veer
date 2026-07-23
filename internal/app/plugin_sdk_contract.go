package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const pluginSDKContractVersion = 6

type pluginSDKAPIContract struct {
	Version        int                              `json:"version"`
	Runtime        pluginSDKRuntimeContract         `json:"runtime"`
	TCPipeline     PluginTCPipelineCapabilities     `json:"tc_pipeline"`
	PacketMetadata PluginPacketMetadataCapabilities `json:"packet_metadata"`
	XDPPipeline    PluginXDPPipelineCapabilities    `json:"xdp_pipeline"`
	EventBus       pluginSDKEventBusContract        `json:"event_bus"`
	Schemas        pluginSDKSchemaContract          `json:"schemas"`
	RingBuffers    pluginSDKRingContract            `json:"ring_buffers"`
	Operations     pluginSDKOperationContract       `json:"operations"`
	Control        pluginSDKControlContract         `json:"control"`
	ControlMethods []string                         `json:"control_methods"`
}

type pluginSDKControlContract struct {
	HostProtocolABI  int                           `json:"host_protocol_abi"`
	MaxCallsPerEvent int                           `json:"max_calls_per_event"`
	MaxJSONDepth     int                           `json:"max_json_depth"`
	MaxRequestBytes  int                           `json:"max_request_bytes"`
	MaxResponseBytes int                           `json:"max_response_bytes"`
	Capabilities     []pluginHostControlCapability `json:"capabilities"`
}

type pluginSDKSchemaContract struct {
	Draft      string `json:"draft"`
	MaxBytes   int    `json:"max_bytes"`
	MaxVersion int    `json:"max_version"`
}

type pluginSDKEventBusContract struct {
	MaxSubscriptions        int      `json:"max_subscriptions"`
	DefaultQueueSize        int      `json:"default_queue_size"`
	MaxQueueSize            int      `json:"max_queue_size"`
	MaxPayloadBytes         int      `json:"max_payload_bytes"`
	MaxAccessEntries        int      `json:"max_access_entries"`
	MaxAccessTopics         int      `json:"max_access_topics"`
	DurableMaxAttempts      int      `json:"durable_max_attempts"`
	DurablePerPluginRecords int      `json:"durable_per_plugin_records"`
	DurableGlobalRecords    int      `json:"durable_global_records"`
	SystemTopics            []string `json:"system_topics"`
}

type pluginSDKRuntimeContract struct {
	APIVersion     string               `json:"api_version"`
	RuntimeVersion string               `json:"runtime_version"`
	ControlAPIABI  int                  `json:"control_api_abi"`
	TCPipelineABI  int                  `json:"tc_pipeline_abi"`
	CorePriority   int                  `json:"core_priority"`
	ResourceLimits PluginResourceLimits `json:"resource_limits"`
	Features       []string             `json:"features"`
}

type pluginSDKRingContract struct {
	MaxSubscriptions       int   `json:"max_subscriptions"`
	DefaultQueueSize       int   `json:"default_queue_size"`
	MaxQueueSize           int   `json:"max_queue_size"`
	DefaultBatchRecords    int   `json:"default_batch_records"`
	MaxBatchRecords        int   `json:"max_batch_records"`
	DefaultBatchBytes      int   `json:"default_batch_bytes"`
	MaxBatchBytes          int   `json:"max_batch_bytes"`
	DefaultPollTimeoutMS   int64 `json:"default_poll_timeout_ms"`
	MaxPollTimeoutMS       int64 `json:"max_poll_timeout_ms"`
	PluginPendingByteLimit int64 `json:"plugin_pending_byte_limit"`
}

type pluginSDKOperationContract struct {
	MaxRecordsPerPlugin int      `json:"max_records_per_plugin"`
	MaxFieldBytes       int      `json:"max_field_bytes"`
	MaxPluginBytes      int      `json:"max_plugin_bytes"`
	DefaultListLimit    int      `json:"default_list_limit"`
	MaxListLimit        int      `json:"max_list_limit"`
	MaxRetryDelayMS     int64    `json:"max_retry_delay_ms"`
	Statuses            []string `json:"statuses"`
}

func currentPluginSDKAPIContract() pluginSDKAPIContract {
	capabilities := pluginRuntimeCapabilities(&Config{})
	return pluginSDKAPIContract{
		Version: pluginSDKContractVersion,
		Runtime: pluginSDKRuntimeContract{
			APIVersion:     pluginAPIVersionV1,
			RuntimeVersion: pluginRuntimeVersion,
			ControlAPIABI:  pluginControlAPIABI,
			TCPipelineABI:  pluginTCPipelineABI,
			CorePriority:   pluginPipelineCorePriority,
			ResourceLimits: pluginResourceLimitsFromConfig(nil),
			Features:       append([]string(nil), pluginRuntimeFeatures...),
		},
		TCPipeline:     capabilities.TCPipeline,
		PacketMetadata: capabilities.PacketMetadata,
		XDPPipeline:    capabilities.XDPPipeline,
		EventBus: pluginSDKEventBusContract{
			MaxSubscriptions:        pluginEventMaxSubscriptions,
			DefaultQueueSize:        pluginEventDefaultQueueSize,
			MaxQueueSize:            pluginEventMaxQueueSize,
			MaxPayloadBytes:         pluginEventMaxPayloadBytes,
			MaxAccessEntries:        pluginEventMaxAccessEntries,
			MaxAccessTopics:         pluginEventMaxAccessTopics,
			DurableMaxAttempts:      pluginEventDurableMaxAttempts,
			DurablePerPluginRecords: pluginEventDurablePerPluginMax,
			DurableGlobalRecords:    pluginEventDurableGlobalMax,
			SystemTopics: []string{
				pluginEventTopicNetLink,
				pluginEventTopicNetAddr,
				pluginEventTopicNetNeigh,
				pluginEventTopicNetRoute,
				pluginEventTopicResourceChanged,
				pluginEventTopicPluginLifecycle,
			},
		},
		Schemas: pluginSDKSchemaContract{
			Draft: "2020-12", MaxBytes: pluginSchemaMaxBytes, MaxVersion: pluginSchemaMaxVersion,
		},
		RingBuffers: pluginSDKRingContract{
			MaxSubscriptions: pluginRingMaxSubscriptions, DefaultQueueSize: pluginRingDefaultQueueSize, MaxQueueSize: pluginRingMaxQueueSize,
			DefaultBatchRecords: pluginRingDefaultBatchRecords, MaxBatchRecords: pluginRingMaxBatchRecords,
			DefaultBatchBytes: pluginRingDefaultBatchBytes, MaxBatchBytes: pluginRingMaxBatchBytes,
			DefaultPollTimeoutMS: pluginRingDefaultPollTimeoutMS, MaxPollTimeoutMS: pluginRingMaxPollTimeoutMS,
			PluginPendingByteLimit: pluginRingPluginPendingByteLimit,
		},
		Operations: pluginSDKOperationContract{
			MaxRecordsPerPlugin: pluginOperationMaxRecordsPerPlugin,
			MaxFieldBytes:       pluginOperationMaxFieldBytes,
			MaxPluginBytes:      pluginOperationMaxPluginBytes,
			DefaultListLimit:    pluginOperationDefaultListLimit,
			MaxListLimit:        pluginOperationMaxListLimit,
			MaxRetryDelayMS:     pluginOperationMaxRetryDelayMS,
			Statuses:            []string{"pending", "running", "retry_wait", "completed", "failed", "cancelled"},
		},
		Control: pluginSDKControlContract{
			HostProtocolABI:  pluginHostProtocolVersion,
			MaxCallsPerEvent: pluginHostMaxCallsPerEvent,
			MaxJSONDepth:     pluginHostMaxJSONDepth,
			MaxRequestBytes:  pluginHostMaxChildFrameBytes,
			MaxResponseBytes: pluginHostMaxParentFrameBytes,
			Capabilities:     append([]pluginHostControlCapability(nil), pluginHostControlCapabilities...),
		},
		ControlMethods: append([]string(nil), pluginHostControlMethods...),
	}
}

func encodePluginSDKAPIContract(contract pluginSDKAPIContract, indent bool) ([]byte, string, error) {
	canonical, err := json.Marshal(contract)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(canonical)
	if !indent {
		return append(canonical, '\n'), hex.EncodeToString(hash[:]), nil
	}
	pretty := &bytes.Buffer{}
	if err := json.Indent(pretty, canonical, "", "  "); err != nil {
		return nil, "", err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), hex.EncodeToString(hash[:]), nil
}

func decodePluginSDKAPIContract(data []byte) (pluginSDKAPIContract, error) {
	if len(data) == 0 || len(data) > pluginPackageMaxEntryBytes {
		return pluginSDKAPIContract{}, fmt.Errorf("plugin SDK contract size is invalid")
	}
	var contract pluginSDKAPIContract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return pluginSDKAPIContract{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return pluginSDKAPIContract{}, fmt.Errorf("plugin SDK contract contains trailing JSON values")
		}
		return pluginSDKAPIContract{}, fmt.Errorf("decode trailing plugin SDK contract content: %w", err)
	}
	return contract, nil
}

func encodePluginSDKMethodTypes(methods []string) ([]byte, error) {
	values := append([]string(nil), methods...)
	sort.Strings(values)
	var output strings.Builder
	output.WriteString("/// <reference path=\"./control.d.ts\" />\n\n")
	output.WriteString("export {};\n\ndeclare global {\n")
	output.WriteString("  interface VeerHostControlMethodMap {\n")
	for index, method := range values {
		if !validPluginSDKMethodName(method) {
			return nil, fmt.Errorf("invalid plugin SDK method %q", method)
		}
		if index > 0 && values[index-1] == method {
			return nil, fmt.Errorf("duplicate plugin SDK method %q", method)
		}
		fmt.Fprintf(&output, "    %q: typeof %s;\n", method, method)
	}
	output.WriteString("  }\n\n")
	output.WriteString("  type VeerHostControlMethod = keyof VeerHostControlMethodMap;\n")
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

func validPluginSDKMethodName(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || !pluginSDKIdentifierStart(part[0]) {
			return false
		}
		for index := 1; index < len(part); index++ {
			if !pluginSDKIdentifierPart(part[index]) {
				return false
			}
		}
	}
	return true
}

func pluginSDKIdentifierStart(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value == '_' || value == '$'
}

func pluginSDKIdentifierPart(value byte) bool {
	return pluginSDKIdentifierStart(value) || value >= '0' && value <= '9'
}
