package app

import "time"

type Rule struct {
	ID               int64  `json:"id"`
	InInterface      string `json:"in_interface"`
	InIP             string `json:"in_ip"`
	InPort           int    `json:"in_port"`
	OutInterface     string `json:"out_interface"`
	OutIP            string `json:"out_ip"`
	OutSourceIP      string `json:"out_source_ip"`
	OutPort          int    `json:"out_port"`
	Protocol         string `json:"protocol"`
	Remark           string `json:"remark"`
	Tag              string `json:"tag"`
	Enabled          bool   `json:"enabled"`
	Transparent      bool   `json:"transparent"`
	EnginePreference string `json:"engine_preference"`

	kernelLogKind    string
	kernelLogOwnerID int64
	kernelMode       string
	kernelNATType    string
}

type Site struct {
	ID              int64  `json:"id"`
	Domain          string `json:"domain"`
	ListenIP        string `json:"listen_ip"`
	ListenIface     string `json:"listen_interface"`
	BackendIP       string `json:"backend_ip"`
	BackendSourceIP string `json:"backend_source_ip"`
	BackendHTTP     int    `json:"backend_http_port"`
	BackendHTTPS    int    `json:"backend_https_port"`
	Tag             string `json:"tag"`
	Enabled         bool   `json:"enabled"`
	Transparent     bool   `json:"transparent"`
}

type PortRange struct {
	ID           int64  `json:"id"`
	InInterface  string `json:"in_interface"`
	InIP         string `json:"in_ip"`
	StartPort    int    `json:"start_port"`
	EndPort      int    `json:"end_port"`
	OutInterface string `json:"out_interface"`
	OutIP        string `json:"out_ip"`
	OutSourceIP  string `json:"out_source_ip"`
	OutStartPort int    `json:"out_start_port"`
	Protocol     string `json:"protocol"`
	Remark       string `json:"remark"`
	Tag          string `json:"tag"`
	Enabled      bool   `json:"enabled"`
	Transparent  bool   `json:"transparent"`
}

type IPCMessage struct {
	Type           string             `json:"type"`
	RuleID         int64              `json:"rule_id,omitempty"`
	WorkerIndex    int                `json:"worker_index,omitempty"`
	Rule           *Rule              `json:"rule,omitempty"`
	Rules          []Rule             `json:"rules,omitempty"`
	Sites          []Site             `json:"sites,omitempty"`
	PortRange      *PortRange         `json:"port_range,omitempty"`
	PortRanges     []PortRange        `json:"port_ranges,omitempty"`
	Status         string             `json:"status,omitempty"`
	Error          string             `json:"error,omitempty"`
	FailedRuleIDs  []int64            `json:"failed_rule_ids,omitempty"`
	FailedRangeIDs []int64            `json:"failed_range_ids,omitempty"`
	FailedSiteIDs  []int64            `json:"failed_site_ids,omitempty"`
	ActiveRuleIDs  []int64            `json:"active_rule_ids,omitempty"`
	ActiveRangeIDs []int64            `json:"active_range_ids,omitempty"`
	Stats          []RuleStatsReport  `json:"stats,omitempty"`
	RangeStats     []RangeStatsReport `json:"range_stats,omitempty"`
	SiteStats      []SiteStatsReport  `json:"site_stats,omitempty"`
	BinaryHash     string             `json:"binary_hash,omitempty"`
}

type InterfaceInfo struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Parent string   `json:"parent,omitempty"`
	Kind   string   `json:"kind,omitempty"`
}

type EgressNAT struct {
	ID              int64  `json:"id"`
	ParentInterface string `json:"parent_interface"`
	ChildInterface  string `json:"child_interface"`
	OutInterface    string `json:"out_interface"`
	OutSourceIP     string `json:"out_source_ip"`
	Protocol        string `json:"protocol"`
	NATType         string `json:"nat_type"`
	Enabled         bool   `json:"enabled"`
}

type EgressNATStatus struct {
	EgressNAT
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine,omitempty"`
	KernelEligible        bool   `json:"kernel_eligible"`
	KernelReason          string `json:"kernel_reason,omitempty"`
	FallbackReason        string `json:"fallback_reason,omitempty"`
}

type RuleStatus struct {
	Rule
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine,omitempty"`
	KernelEligible        bool   `json:"kernel_eligible"`
	KernelReason          string `json:"kernel_reason,omitempty"`
	FallbackReason        string `json:"fallback_reason,omitempty"`
}

type SiteStatus struct {
	Site
	Status string `json:"status"`
}

type PortRangeStatus struct {
	PortRange
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine,omitempty"`
	KernelEligible        bool   `json:"kernel_eligible"`
	KernelReason          string `json:"kernel_reason,omitempty"`
	FallbackReason        string `json:"fallback_reason,omitempty"`
}

type WorkerView struct {
	Kind           string            `json:"kind"`
	Index          int               `json:"index"`
	Status         string            `json:"status"`
	BinaryHash     string            `json:"binary_hash,omitempty"`
	RuleCount      int               `json:"rule_count,omitempty"`
	RangeCount     int               `json:"range_count,omitempty"`
	SiteCount      int               `json:"site_count,omitempty"`
	EgressNATCount int               `json:"egress_nat_count,omitempty"`
	Rules          []RuleStatus      `json:"rules,omitempty"`
	Ranges         []PortRangeStatus `json:"ranges,omitempty"`
	EgressNATs     []EgressNATStatus `json:"egress_nats,omitempty"`
}

type WorkerListResponse struct {
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	Total      int          `json:"total"`
	BinaryHash string       `json:"binary_hash"`
	Workers    []WorkerView `json:"workers"`
}

type RuleStatsListItem struct {
	RuleStatsReport
	Remark       string `json:"remark"`
	CurrentConns int64  `json:"-"`
}

type RuleStatsListResponse struct {
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
	Total    int                 `json:"total"`
	SortKey  string              `json:"sort_key,omitempty"`
	SortAsc  bool                `json:"sort_asc"`
	Items    []RuleStatsListItem `json:"items"`
}

type RuleStatsReport struct {
	RuleID        int64 `json:"rule_id"`
	ActiveConns   int64 `json:"active_conns"`
	TotalConns    int64 `json:"total_conns"`
	RejectedConns int64 `json:"rejected_conns"`
	BytesIn       int64 `json:"bytes_in"`
	BytesOut      int64 `json:"bytes_out"`
	SpeedIn       int64 `json:"speed_in"`
	SpeedOut      int64 `json:"speed_out"`
	NatTableSize  int   `json:"nat_table_size"`
}

type RuleCurrentConnsReport struct {
	RuleID       int64 `json:"rule_id"`
	CurrentConns int64 `json:"current_conns"`
}

type RangeStatsReport struct {
	RangeID       int64 `json:"range_id"`
	ActiveConns   int64 `json:"active_conns"`
	TotalConns    int64 `json:"total_conns"`
	RejectedConns int64 `json:"rejected_conns"`
	BytesIn       int64 `json:"bytes_in"`
	BytesOut      int64 `json:"bytes_out"`
	SpeedIn       int64 `json:"speed_in"`
	SpeedOut      int64 `json:"speed_out"`
	NatTableSize  int   `json:"nat_table_size"`
}

type RangeCurrentConnsReport struct {
	RangeID      int64 `json:"range_id"`
	CurrentConns int64 `json:"current_conns"`
}

type RangeStatsListItem struct {
	RangeStatsReport
	Remark       string `json:"remark"`
	CurrentConns int64  `json:"-"`
}

type RangeStatsListResponse struct {
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	Total    int                  `json:"total"`
	SortKey  string               `json:"sort_key,omitempty"`
	SortAsc  bool                 `json:"sort_asc"`
	Items    []RangeStatsListItem `json:"items"`
}

type EgressNATStatsReport struct {
	EgressNATID  int64 `json:"egress_nat_id"`
	ActiveConns  int64 `json:"active_conns"`
	TotalConns   int64 `json:"total_conns"`
	BytesIn      int64 `json:"bytes_in"`
	BytesOut     int64 `json:"bytes_out"`
	SpeedIn      int64 `json:"speed_in"`
	SpeedOut     int64 `json:"speed_out"`
	NatTableSize int   `json:"nat_table_size"`
}

type EgressNATCurrentConnsReport struct {
	EgressNATID  int64 `json:"egress_nat_id"`
	CurrentConns int64 `json:"current_conns"`
}

type EgressNATStatsListItem struct {
	EgressNATStatsReport
	ParentInterface string `json:"parent_interface"`
	ChildInterface  string `json:"child_interface"`
	OutInterface    string `json:"out_interface"`
	OutSourceIP     string `json:"out_source_ip"`
	Protocol        string `json:"protocol"`
	NATType         string `json:"nat_type"`
	CurrentConns    int64  `json:"-"`
}

type EgressNATStatsListResponse struct {
	Page     int                      `json:"page"`
	PageSize int                      `json:"page_size"`
	Total    int                      `json:"total"`
	SortKey  string                   `json:"sort_key,omitempty"`
	SortAsc  bool                     `json:"sort_asc"`
	Items    []EgressNATStatsListItem `json:"items"`
}

type SiteStatsReport struct {
	SiteID      int64  `json:"site_id"`
	Domain      string `json:"domain"`
	ActiveConns int64  `json:"active_conns"`
	TotalConns  int64  `json:"total_conns"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	SpeedIn     int64  `json:"speed_in"`
	SpeedOut    int64  `json:"speed_out"`
}

type SiteCurrentConnsReport struct {
	SiteID       int64 `json:"site_id"`
	CurrentConns int64 `json:"current_conns"`
}

type CurrentConnsResponse struct {
	Rules      []RuleCurrentConnsReport      `json:"rules"`
	Ranges     []RangeCurrentConnsReport     `json:"ranges"`
	Sites      []SiteCurrentConnsReport      `json:"sites"`
	EgressNATs []EgressNATCurrentConnsReport `json:"egress_nats"`
}

type KernelEngineRuntimeView struct {
	Name                          string    `json:"name"`
	Available                     bool      `json:"available"`
	AvailableReason               string    `json:"available_reason,omitempty"`
	PressureActive                bool      `json:"pressure_active"`
	PressureLevel                 string    `json:"pressure_level,omitempty"`
	PressureReason                string    `json:"pressure_reason,omitempty"`
	PressureSince                 time.Time `json:"pressure_since,omitempty"`
	Degraded                      bool      `json:"degraded"`
	DegradedReason                string    `json:"degraded_reason,omitempty"`
	DegradedSince                 time.Time `json:"degraded_since,omitempty"`
	Loaded                        bool      `json:"loaded"`
	ActiveEntries                 int       `json:"active_entries"`
	Attachments                   int       `json:"attachments"`
	AttachmentsHealthy            bool      `json:"attachments_healthy"`
	AttachmentSummary             string    `json:"attachment_summary,omitempty"`
	AttachmentsUnhealthyCount     int       `json:"attachments_unhealthy_count,omitempty"`
	LastAttachmentsUnhealthyAt    time.Time `json:"last_attachments_unhealthy_at,omitempty"`
	RulesMapEntries               int       `json:"rules_map_entries"`
	RulesMapCapacity              int       `json:"rules_map_capacity"`
	RulesMapEntriesV4             int       `json:"rules_map_entries_v4,omitempty"`
	RulesMapCapacityV4            int       `json:"rules_map_capacity_v4,omitempty"`
	RulesMapEntriesV6             int       `json:"rules_map_entries_v6,omitempty"`
	RulesMapCapacityV6            int       `json:"rules_map_capacity_v6,omitempty"`
	FlowsMapEntries               int       `json:"flows_map_entries"`
	FlowsMapCapacity              int       `json:"flows_map_capacity"`
	FlowsMapEntriesV4             int       `json:"flows_map_entries_v4,omitempty"`
	FlowsMapCapacityV4            int       `json:"flows_map_capacity_v4,omitempty"`
	FlowsMapEntriesV6             int       `json:"flows_map_entries_v6,omitempty"`
	FlowsMapCapacityV6            int       `json:"flows_map_capacity_v6,omitempty"`
	NATMapEntries                 int       `json:"nat_map_entries,omitempty"`
	NATMapCapacity                int       `json:"nat_map_capacity,omitempty"`
	NATMapEntriesV4               int       `json:"nat_map_entries_v4,omitempty"`
	NATMapCapacityV4              int       `json:"nat_map_capacity_v4,omitempty"`
	NATMapEntriesV6               int       `json:"nat_map_entries_v6,omitempty"`
	NATMapCapacityV6              int       `json:"nat_map_capacity_v6,omitempty"`
	LastReconcileMode             string    `json:"last_reconcile_mode,omitempty"`
	TrafficStats                  bool      `json:"traffic_stats"`
	Diagnostics                   bool      `json:"diagnostics"`
	DiagnosticsVerbose            bool      `json:"diagnostics_verbose"`
	DiagFIBNonSuccess             uint64    `json:"diag_fib_non_success,omitempty"`
	DiagRedirectNeighUsed         uint64    `json:"diag_redirect_neigh_used,omitempty"`
	DiagRedirectDrop              uint64    `json:"diag_redirect_drop,omitempty"`
	DiagNATReserveFail            uint64    `json:"diag_nat_reserve_fail,omitempty"`
	DiagNATSelfHealInsert         uint64    `json:"diag_nat_self_heal_insert,omitempty"`
	DiagFlowUpdateFail            uint64    `json:"diag_flow_update_fail,omitempty"`
	DiagNATUpdateFail             uint64    `json:"diag_nat_update_fail,omitempty"`
	DiagRewriteFail               uint64    `json:"diag_rewrite_fail,omitempty"`
	DiagNATProbeRound2Used        uint64    `json:"diag_nat_probe_round2_used,omitempty"`
	DiagNATProbeRound3Used        uint64    `json:"diag_nat_probe_round3_used,omitempty"`
	DiagReplyFlowRecreated        uint64    `json:"diag_reply_flow_recreated,omitempty"`
	DiagTCPCloseDelete            uint64    `json:"diag_tcp_close_delete,omitempty"`
	DiagSnapshotError             string    `json:"diag_snapshot_error,omitempty"`
	LastReconcileAt               time.Time `json:"last_reconcile_at,omitempty"`
	LastReconcileMs               int64     `json:"last_reconcile_ms,omitempty"`
	LastReconcileError            string    `json:"last_reconcile_error,omitempty"`
	LastReconcileRequestEntries   int       `json:"last_reconcile_request_entries,omitempty"`
	LastReconcilePreparedEntries  int       `json:"last_reconcile_prepared_entries,omitempty"`
	LastReconcileAppliedEntries   int       `json:"last_reconcile_applied_entries,omitempty"`
	LastReconcileUpserts          int       `json:"last_reconcile_upserts,omitempty"`
	LastReconcileDeletes          int       `json:"last_reconcile_deletes,omitempty"`
	LastReconcileAttaches         int       `json:"last_reconcile_attaches,omitempty"`
	LastReconcileDetaches         int       `json:"last_reconcile_detaches,omitempty"`
	LastReconcilePreserved        int       `json:"last_reconcile_preserved,omitempty"`
	LastReconcileFlowPurgeDeleted int       `json:"last_reconcile_flow_purge_deleted,omitempty"`
	LastReconcilePrepareMs        int64     `json:"last_reconcile_prepare_ms,omitempty"`
	LastReconcileAttachMs         int64     `json:"last_reconcile_attach_ms,omitempty"`
	LastReconcileFlowPurgeMs      int64     `json:"last_reconcile_flow_purge_ms,omitempty"`
	LastMaintainAt                time.Time `json:"last_maintain_at,omitempty"`
	LastMaintainMs                int64     `json:"last_maintain_ms,omitempty"`
	LastMaintainError             string    `json:"last_maintain_error,omitempty"`
	LastPruneBudget               int       `json:"last_prune_budget,omitempty"`
	LastPruneScanned              int       `json:"last_prune_scanned,omitempty"`
	LastPruneDeleted              int       `json:"last_prune_deleted,omitempty"`
}

type KernelRuntimeResponse struct {
	Available                                      bool                      `json:"available"`
	AvailableReason                                string                    `json:"available_reason,omitempty"`
	DefaultEngine                                  string                    `json:"default_engine"`
	ConfiguredOrder                                []string                  `json:"configured_order"`
	TrafficStats                                   bool                      `json:"traffic_stats"`
	TCDiagnostics                                  bool                      `json:"tc_diagnostics"`
	TCDiagnosticsVerbose                           bool                      `json:"tc_diagnostics_verbose"`
	KernelMapProfile                               string                    `json:"kernel_map_profile,omitempty"`
	KernelMapTotalMemoryBytes                      uint64                    `json:"kernel_map_total_memory_bytes,omitempty"`
	KernelRulesMapBaseLimit                        int                       `json:"kernel_rules_map_base_limit,omitempty"`
	KernelFlowsMapBaseLimit                        int                       `json:"kernel_flows_map_base_limit,omitempty"`
	KernelNATMapBaseLimit                          int                       `json:"kernel_nat_map_base_limit,omitempty"`
	KernelEgressNATAutoFloor                       int                       `json:"kernel_egress_nat_auto_floor,omitempty"`
	KernelRulesMapConfiguredLimit                  int                       `json:"kernel_rules_map_configured_limit,omitempty"`
	KernelFlowsMapConfiguredLimit                  int                       `json:"kernel_flows_map_configured_limit,omitempty"`
	KernelNATMapConfiguredLimit                    int                       `json:"kernel_nat_map_configured_limit,omitempty"`
	KernelRulesMapCapacityMode                     string                    `json:"kernel_rules_map_capacity_mode,omitempty"`
	KernelFlowsMapCapacityMode                     string                    `json:"kernel_flows_map_capacity_mode,omitempty"`
	KernelNATMapCapacityMode                       string                    `json:"kernel_nat_map_capacity_mode,omitempty"`
	ActiveRuleCount                                int                       `json:"active_rule_count"`
	ActiveRangeCount                               int                       `json:"active_range_count"`
	KernelFallbackRuleCount                        int                       `json:"kernel_fallback_rule_count"`
	KernelFallbackRangeCount                       int                       `json:"kernel_fallback_range_count"`
	TransientFallbackRuleCount                     int                       `json:"transient_fallback_rule_count"`
	TransientFallbackRangeCount                    int                       `json:"transient_fallback_range_count"`
	TransientFallbackSummary                       string                    `json:"transient_fallback_summary,omitempty"`
	RetryPending                                   bool                      `json:"retry_pending"`
	KernelRetryCount                               int                       `json:"kernel_retry_count"`
	LastKernelRetryAt                              time.Time                 `json:"last_kernel_retry_at,omitempty"`
	LastKernelRetryReason                          string                    `json:"last_kernel_retry_reason,omitempty"`
	KernelIncrementalRetryCount                    int                       `json:"kernel_incremental_retry_count"`
	KernelIncrementalRetryFallbackCount            int                       `json:"kernel_incremental_retry_fallback_count"`
	CooldownRuleOwnerCount                         int                       `json:"cooldown_rule_owner_count"`
	CooldownRangeOwnerCount                        int                       `json:"cooldown_range_owner_count"`
	CooldownSummary                                string                    `json:"cooldown_summary,omitempty"`
	CooldownNextExpiryAt                           time.Time                 `json:"cooldown_next_expiry_at,omitempty"`
	CooldownClearAt                                time.Time                 `json:"cooldown_clear_at,omitempty"`
	LastKernelIncrementalRetryAt                   time.Time                 `json:"last_kernel_incremental_retry_at,omitempty"`
	LastKernelIncrementalRetryResult               string                    `json:"last_kernel_incremental_retry_result,omitempty"`
	LastKernelIncrementalRetryMatchedRuleOwners    int                       `json:"last_kernel_incremental_retry_matched_rule_owners"`
	LastKernelIncrementalRetryMatchedRangeOwners   int                       `json:"last_kernel_incremental_retry_matched_range_owners"`
	LastKernelIncrementalRetryAttemptedRuleOwners  int                       `json:"last_kernel_incremental_retry_attempted_rule_owners"`
	LastKernelIncrementalRetryAttemptedRangeOwners int                       `json:"last_kernel_incremental_retry_attempted_range_owners"`
	LastKernelIncrementalRetryRetainedRuleOwners   int                       `json:"last_kernel_incremental_retry_retained_rule_owners"`
	LastKernelIncrementalRetryRetainedRangeOwners  int                       `json:"last_kernel_incremental_retry_retained_range_owners"`
	LastKernelIncrementalRetryRecoveredRuleOwners  int                       `json:"last_kernel_incremental_retry_recovered_rule_owners"`
	LastKernelIncrementalRetryRecoveredRangeOwners int                       `json:"last_kernel_incremental_retry_recovered_range_owners"`
	LastKernelIncrementalRetryCooldownRuleOwners   int                       `json:"last_kernel_incremental_retry_cooldown_rule_owners"`
	LastKernelIncrementalRetryCooldownRangeOwners  int                       `json:"last_kernel_incremental_retry_cooldown_range_owners"`
	LastKernelIncrementalRetryCooldownSummary      string                    `json:"last_kernel_incremental_retry_cooldown_summary,omitempty"`
	LastKernelIncrementalRetryCooldownScope        string                    `json:"last_kernel_incremental_retry_cooldown_scope,omitempty"`
	LastKernelIncrementalRetryBackoffRuleOwners    int                       `json:"last_kernel_incremental_retry_backoff_rule_owners"`
	LastKernelIncrementalRetryBackoffRangeOwners   int                       `json:"last_kernel_incremental_retry_backoff_range_owners"`
	LastKernelIncrementalRetryBackoffSummary       string                    `json:"last_kernel_incremental_retry_backoff_summary,omitempty"`
	LastKernelIncrementalRetryBackoffScope         string                    `json:"last_kernel_incremental_retry_backoff_scope,omitempty"`
	LastKernelIncrementalRetryBackoffMaxFailures   int                       `json:"last_kernel_incremental_retry_backoff_max_failures"`
	LastKernelIncrementalRetryBackoffMaxDelayMs    int64                     `json:"last_kernel_incremental_retry_backoff_max_delay_ms,omitempty"`
	KernelNetlinkRecoverPending                    bool                      `json:"kernel_netlink_recover_pending"`
	KernelNetlinkRecoverSource                     string                    `json:"kernel_netlink_recover_source,omitempty"`
	KernelNetlinkRecoverSummary                    string                    `json:"kernel_netlink_recover_summary,omitempty"`
	KernelNetlinkRecoverRequestedAt                time.Time                 `json:"kernel_netlink_recover_requested_at,omitempty"`
	KernelNetlinkRecoverTriggerSummary             string                    `json:"kernel_netlink_recover_trigger_summary,omitempty"`
	LastKernelAttachmentIssue                      string                    `json:"last_kernel_attachment_issue,omitempty"`
	LastKernelAttachmentHealAt                     time.Time                 `json:"last_kernel_attachment_heal_at,omitempty"`
	LastKernelAttachmentHealSummary                string                    `json:"last_kernel_attachment_heal_summary,omitempty"`
	LastKernelAttachmentHealError                  string                    `json:"last_kernel_attachment_heal_error,omitempty"`
	LastStatsSnapshotAt                            time.Time                 `json:"last_stats_snapshot_at,omitempty"`
	LastStatsSnapshotMs                            int64                     `json:"last_stats_snapshot_ms,omitempty"`
	LastStatsSnapshotError                         string                    `json:"last_stats_snapshot_error,omitempty"`
	Engines                                        []KernelEngineRuntimeView `json:"engines"`
}
