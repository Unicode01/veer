package main

type Rule struct {
	ID               int64  `json:"id"`
	InInterface      string `json:"in_interface"`
	InIP             string `json:"in_ip"`
	InPort           int    `json:"in_port"`
	OutInterface     string `json:"out_interface"`
	OutIP            string `json:"out_ip"`
	OutPort          int    `json:"out_port"`
	Protocol         string `json:"protocol"`
	Remark           string `json:"remark"`
	Tag              string `json:"tag"`
	Enabled          bool   `json:"enabled"`
	Transparent      bool   `json:"transparent"`
	EnginePreference string `json:"engine_preference"`
}

type Site struct {
	ID           int64  `json:"id"`
	Domain       string `json:"domain"`
	ListenIP     string `json:"listen_ip"`
	ListenIface  string `json:"listen_interface"`
	BackendIP    string `json:"backend_ip"`
	BackendHTTP  int    `json:"backend_http_port"`
	BackendHTTPS int    `json:"backend_https_port"`
	Tag          string `json:"tag"`
	Enabled      bool   `json:"enabled"`
	Transparent  bool   `json:"transparent"`
}

type PortRange struct {
	ID           int64  `json:"id"`
	InInterface  string `json:"in_interface"`
	InIP         string `json:"in_ip"`
	StartPort    int    `json:"start_port"`
	EndPort      int    `json:"end_port"`
	OutInterface string `json:"out_interface"`
	OutIP        string `json:"out_ip"`
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
	ActiveRuleIDs  []int64            `json:"active_rule_ids,omitempty"`
	ActiveRangeIDs []int64            `json:"active_range_ids,omitempty"`
	Stats          []RuleStatsReport  `json:"stats,omitempty"`
	RangeStats     []RangeStatsReport `json:"range_stats,omitempty"`
	SiteStats      []SiteStatsReport  `json:"site_stats,omitempty"`
	BinaryHash     string             `json:"binary_hash,omitempty"`
}

type InterfaceInfo struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

type RuleStatus struct {
	Rule
	Status          string `json:"status"`
	EffectiveEngine string `json:"effective_engine"`
	KernelEligible  bool   `json:"kernel_eligible"`
	KernelReason    string `json:"kernel_reason,omitempty"`
	FallbackReason  string `json:"fallback_reason,omitempty"`
}

type SiteStatus struct {
	Site
	Status string `json:"status"`
}

type PortRangeStatus struct {
	PortRange
	Status          string `json:"status"`
	EffectiveEngine string `json:"effective_engine"`
	KernelEligible  bool   `json:"kernel_eligible"`
	KernelReason    string `json:"kernel_reason,omitempty"`
	FallbackReason  string `json:"fallback_reason,omitempty"`
}

type WorkerView struct {
	Kind       string            `json:"kind"`
	Index      int               `json:"index"`
	Status     string            `json:"status"`
	BinaryHash string            `json:"binary_hash,omitempty"`
	RuleCount  int               `json:"rule_count,omitempty"`
	RangeCount int               `json:"range_count,omitempty"`
	SiteCount  int               `json:"site_count,omitempty"`
	Rules      []RuleStatus      `json:"rules,omitempty"`
	Ranges     []PortRangeStatus `json:"ranges,omitempty"`
}

type WorkerListResponse struct {
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	Total      int          `json:"total"`
	BinaryHash string       `json:"binary_hash"`
	Workers    []WorkerView `json:"workers"`
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
