package app

import (
	"database/sql"

	"forward/internal/store"
)

type dbIndexDefinition = store.IndexDefinition
type dbConstraintIndexDefinition = store.ConstraintIndexDefinition
type sqlRuleStore = store.RuleStore

const (
	dbBusyTimeoutMillis                                   = 5000
	dbTxLockMode                                          = "immediate"
	dbByIDQueryChunkSize                                  = 500
	dbConstraintIndexSitesHTTPDomainEnabled               = store.ConstraintIndexSitesHTTPDomainEnabled
	dbConstraintIndexSitesHTTPSDomainEnabled              = store.ConstraintIndexSitesHTTPSDomainEnabled
	dbConstraintIndexManagedNetworkReservationNetworkMAC  = store.ConstraintIndexManagedNetworkReservationNetworkMAC
	dbConstraintIndexManagedNetworkReservationNetworkIPv4 = store.ConstraintIndexManagedNetworkReservationNetworkIPv4
)

var schema = store.Schema
var schemaIndexes = store.SchemaIndexes
var schemaConstraintIndexes = store.SchemaConstraintIndexes

func initDB(path string) (*sql.DB, error) {
	return store.InitDB(path)
}

func ensureTable(db *sql.DB, table string, columns [][2]string) error {
	return store.EnsureTable(db, table, columns)
}

func ensureIndexes(db *sql.DB, indexes []dbIndexDefinition) error {
	return store.EnsureIndexes(db, indexes)
}

func ensureIndex(db *sql.DB, index dbIndexDefinition) error {
	return store.EnsureIndex(db, index)
}

func ensureConstraintIndexes(db *sql.DB, indexes []dbConstraintIndexDefinition) error {
	return store.EnsureConstraintIndexes(db, indexes)
}

func ensureConstraintIndex(db *sql.DB, index dbConstraintIndexDefinition) error {
	return store.EnsureConstraintIndex(db, index)
}

func dbIndexExists(db *sql.DB, name string) (bool, error) {
	return store.DBIndexExists(db, name)
}

func sqliteUniqueConstraintIndexName(err error) string {
	return store.SQLiteUniqueConstraintIndexName(err)
}

func toStoreRule(r Rule) store.Rule {
	return store.Rule{
		ID:               r.ID,
		InInterface:      r.InInterface,
		InIP:             r.InIP,
		InPort:           r.InPort,
		OutInterface:     r.OutInterface,
		OutIP:            r.OutIP,
		OutSourceIP:      r.OutSourceIP,
		OutPort:          r.OutPort,
		Protocol:         r.Protocol,
		Remark:           r.Remark,
		Tag:              r.Tag,
		Enabled:          r.Enabled,
		Transparent:      r.Transparent,
		EnginePreference: normalizeRuleEnginePreference(r.EnginePreference),
	}
}

func fromStoreRule(item store.Rule) Rule {
	return Rule{
		ID:               item.ID,
		InInterface:      item.InInterface,
		InIP:             item.InIP,
		InPort:           item.InPort,
		OutInterface:     item.OutInterface,
		OutIP:            item.OutIP,
		OutSourceIP:      item.OutSourceIP,
		OutPort:          item.OutPort,
		Protocol:         item.Protocol,
		Remark:           item.Remark,
		Tag:              item.Tag,
		Enabled:          item.Enabled,
		Transparent:      item.Transparent,
		EnginePreference: normalizeRuleEnginePreference(item.EnginePreference),
	}
}

func fromStoreRuleSlice(items []store.Rule) []Rule {
	out := make([]Rule, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreRule(item))
	}
	return out
}

func fromStoreRuleMap(items map[int64]store.Rule) map[int64]Rule {
	out := make(map[int64]Rule, len(items))
	for id, item := range items {
		out[id] = fromStoreRule(item)
	}
	return out
}

func toStoreSite(item Site) store.Site {
	return store.Site{
		ID:              item.ID,
		Domain:          item.Domain,
		ListenIP:        item.ListenIP,
		ListenIface:     item.ListenIface,
		BackendIP:       item.BackendIP,
		BackendSourceIP: item.BackendSourceIP,
		BackendHTTP:     item.BackendHTTP,
		BackendHTTPS:    item.BackendHTTPS,
		Tag:             item.Tag,
		Enabled:         item.Enabled,
		Transparent:     item.Transparent,
	}
}

func fromStoreSite(item store.Site) Site {
	return Site{
		ID:              item.ID,
		Domain:          item.Domain,
		ListenIP:        item.ListenIP,
		ListenIface:     item.ListenIface,
		BackendIP:       item.BackendIP,
		BackendSourceIP: item.BackendSourceIP,
		BackendHTTP:     item.BackendHTTP,
		BackendHTTPS:    item.BackendHTTPS,
		Tag:             item.Tag,
		Enabled:         item.Enabled,
		Transparent:     item.Transparent,
	}
}

func fromStoreSiteSlice(items []store.Site) []Site {
	out := make([]Site, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreSite(item))
	}
	return out
}

func toStorePortRange(item PortRange) store.PortRange {
	return store.PortRange{
		ID:           item.ID,
		InInterface:  item.InInterface,
		InIP:         item.InIP,
		StartPort:    item.StartPort,
		EndPort:      item.EndPort,
		OutInterface: item.OutInterface,
		OutIP:        item.OutIP,
		OutSourceIP:  item.OutSourceIP,
		OutStartPort: item.OutStartPort,
		Protocol:     item.Protocol,
		Remark:       item.Remark,
		Tag:          item.Tag,
		Enabled:      item.Enabled,
		Transparent:  item.Transparent,
	}
}

func fromStorePortRange(item store.PortRange) PortRange {
	return PortRange{
		ID:           item.ID,
		InInterface:  item.InInterface,
		InIP:         item.InIP,
		StartPort:    item.StartPort,
		EndPort:      item.EndPort,
		OutInterface: item.OutInterface,
		OutIP:        item.OutIP,
		OutSourceIP:  item.OutSourceIP,
		OutStartPort: item.OutStartPort,
		Protocol:     item.Protocol,
		Remark:       item.Remark,
		Tag:          item.Tag,
		Enabled:      item.Enabled,
		Transparent:  item.Transparent,
	}
}

func fromStorePortRangeSlice(items []store.PortRange) []PortRange {
	out := make([]PortRange, 0, len(items))
	for _, item := range items {
		out = append(out, fromStorePortRange(item))
	}
	return out
}

func fromStorePortRangeMap(items map[int64]store.PortRange) map[int64]PortRange {
	out := make(map[int64]PortRange, len(items))
	for id, item := range items {
		out[id] = fromStorePortRange(item)
	}
	return out
}

func toStoreEgressNAT(item EgressNAT) store.EgressNAT {
	item.Protocol = normalizeEgressNATProtocol(item.Protocol)
	item.NATType = normalizeEgressNATType(item.NATType)
	return store.EgressNAT{
		ID:              item.ID,
		ParentInterface: item.ParentInterface,
		ChildInterface:  item.ChildInterface,
		OutInterface:    item.OutInterface,
		OutSourceIP:     item.OutSourceIP,
		Protocol:        item.Protocol,
		NATType:         item.NATType,
		Enabled:         item.Enabled,
	}
}

func fromStoreEgressNAT(item store.EgressNAT) EgressNAT {
	return EgressNAT{
		ID:              item.ID,
		ParentInterface: item.ParentInterface,
		ChildInterface:  item.ChildInterface,
		OutInterface:    item.OutInterface,
		OutSourceIP:     item.OutSourceIP,
		Protocol:        normalizeEgressNATProtocol(item.Protocol),
		NATType:         normalizeEgressNATType(item.NATType),
		Enabled:         item.Enabled,
	}
}

func fromStoreEgressNATSlice(items []store.EgressNAT) []EgressNAT {
	out := make([]EgressNAT, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreEgressNAT(item))
	}
	return out
}

func normalizeProtocolMap(values map[int64]string, normalize func(string) string) map[int64]string {
	out := make(map[int64]string, len(values))
	for id, value := range values {
		out[id] = normalize(value)
	}
	return out
}

func toStoreIPv6Assignment(item IPv6Assignment) store.IPv6Assignment {
	hydrateIPv6AssignmentCompatibilityFields(&item)
	return store.IPv6Assignment{
		ID:              item.ID,
		ParentInterface: item.ParentInterface,
		TargetInterface: item.TargetInterface,
		ParentPrefix:    item.ParentPrefix,
		AssignedPrefix:  item.AssignedPrefix,
		Address:         item.Address,
		PrefixLen:       item.PrefixLen,
		Remark:          item.Remark,
		Enabled:         item.Enabled,
	}
}

func fromStoreIPv6Assignment(item store.IPv6Assignment) IPv6Assignment {
	out := IPv6Assignment{
		ID:              item.ID,
		ParentInterface: item.ParentInterface,
		TargetInterface: item.TargetInterface,
		ParentPrefix:    item.ParentPrefix,
		AssignedPrefix:  item.AssignedPrefix,
		Address:         item.Address,
		PrefixLen:       item.PrefixLen,
		Remark:          item.Remark,
		Enabled:         item.Enabled,
	}
	hydrateIPv6AssignmentCompatibilityFields(&out)
	return out
}

func fromStoreIPv6AssignmentSlice(items []store.IPv6Assignment) []IPv6Assignment {
	out := make([]IPv6Assignment, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreIPv6Assignment(item))
	}
	return out
}

func toStoreManagedNetwork(item ManagedNetwork) store.ManagedNetwork {
	item = normalizeManagedNetwork(item)
	return store.ManagedNetwork{
		ID:                  item.ID,
		Name:                item.Name,
		BridgeMode:          item.BridgeMode,
		Bridge:              item.Bridge,
		BridgeMTU:           item.BridgeMTU,
		BridgeVLANAware:     item.BridgeVLANAware,
		UplinkInterface:     item.UplinkInterface,
		IPv4Enabled:         item.IPv4Enabled,
		IPv4CIDR:            item.IPv4CIDR,
		IPv4Gateway:         item.IPv4Gateway,
		IPv4PoolStart:       item.IPv4PoolStart,
		IPv4PoolEnd:         item.IPv4PoolEnd,
		IPv4DNSServers:      item.IPv4DNSServers,
		IPv6Enabled:         item.IPv6Enabled,
		IPv6ParentInterface: item.IPv6ParentInterface,
		IPv6ParentPrefix:    item.IPv6ParentPrefix,
		IPv6AssignmentMode:  item.IPv6AssignmentMode,
		AutoEgressNAT:       item.AutoEgressNAT,
		Remark:              item.Remark,
		Enabled:             item.Enabled,
	}
}

func fromStoreManagedNetwork(item store.ManagedNetwork) ManagedNetwork {
	return normalizeManagedNetwork(ManagedNetwork{
		ID:                  item.ID,
		Name:                item.Name,
		BridgeMode:          item.BridgeMode,
		Bridge:              item.Bridge,
		BridgeMTU:           item.BridgeMTU,
		BridgeVLANAware:     item.BridgeVLANAware,
		UplinkInterface:     item.UplinkInterface,
		IPv4Enabled:         item.IPv4Enabled,
		IPv4CIDR:            item.IPv4CIDR,
		IPv4Gateway:         item.IPv4Gateway,
		IPv4PoolStart:       item.IPv4PoolStart,
		IPv4PoolEnd:         item.IPv4PoolEnd,
		IPv4DNSServers:      item.IPv4DNSServers,
		IPv6Enabled:         item.IPv6Enabled,
		IPv6ParentInterface: item.IPv6ParentInterface,
		IPv6ParentPrefix:    item.IPv6ParentPrefix,
		IPv6AssignmentMode:  item.IPv6AssignmentMode,
		AutoEgressNAT:       item.AutoEgressNAT,
		Remark:              item.Remark,
		Enabled:             item.Enabled,
	})
}

func fromStoreManagedNetworkSlice(items []store.ManagedNetwork) []ManagedNetwork {
	out := make([]ManagedNetwork, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreManagedNetwork(item))
	}
	return out
}

func toStoreManagedNetworkReservation(item ManagedNetworkReservation) store.ManagedNetworkReservation {
	return store.ManagedNetworkReservation{
		ID:               item.ID,
		ManagedNetworkID: item.ManagedNetworkID,
		MACAddress:       item.MACAddress,
		IPv4Address:      item.IPv4Address,
		Remark:           item.Remark,
	}
}

func fromStoreManagedNetworkReservation(item store.ManagedNetworkReservation) ManagedNetworkReservation {
	return ManagedNetworkReservation{
		ID:               item.ID,
		ManagedNetworkID: item.ManagedNetworkID,
		MACAddress:       item.MACAddress,
		IPv4Address:      item.IPv4Address,
		Remark:           item.Remark,
	}
}

func fromStoreManagedNetworkReservationSlice(items []store.ManagedNetworkReservation) []ManagedNetworkReservation {
	out := make([]ManagedNetworkReservation, 0, len(items))
	for _, item := range items {
		out = append(out, fromStoreManagedNetworkReservation(item))
	}
	return out
}

func dbAddRule(db sqlRuleStore, r *Rule) (int64, error) {
	item := toStoreRule(*r)
	return store.AddRule(db, &item)
}

func dbUpdateRule(db sqlRuleStore, r *Rule) error {
	item := toStoreRule(*r)
	return store.UpdateRule(db, &item)
}

func dbDeleteRule(db sqlRuleStore, id int64) error {
	return store.DeleteRule(db, id)
}

func dbGetRules(db sqlRuleStore) ([]Rule, error) {
	items, err := store.GetRules(db)
	if err != nil {
		return nil, err
	}
	return fromStoreRuleSlice(items), nil
}

func dbGetEnabledRules(db sqlRuleStore) ([]Rule, error) {
	items, err := store.GetEnabledRules(db)
	if err != nil {
		return nil, err
	}
	return fromStoreRuleSlice(items), nil
}

func dbGetRulesByIDs(db sqlRuleStore, ids []int64) ([]Rule, error) {
	items, err := store.GetRulesByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStoreRuleSlice(items), nil
}

func dbGetRulesFiltered(db sqlRuleStore, filters ruleFilter) ([]Rule, error) {
	items, err := store.GetRulesFiltered(db, store.RuleFilter{
		IDs:          filters.IDs,
		Tags:         filters.Tags,
		Protocols:    filters.Protocols,
		Statuses:     filters.Statuses,
		Enabled:      filters.Enabled,
		Transparent:  filters.Transparent,
		InInterface:  filters.InInterface,
		OutInterface: filters.OutInterface,
		InIP:         filters.InIP,
		OutIP:        filters.OutIP,
		OutSourceIP:  filters.OutSourceIP,
		InPort:       filters.InPort,
		OutPort:      filters.OutPort,
		Query:        filters.Query,
	})
	if err != nil {
		return nil, err
	}
	return fromStoreRuleSlice(items), nil
}

func dbGetEnabledRulesByIDs(db sqlRuleStore, ids []int64) ([]Rule, error) {
	items, err := store.GetEnabledRulesByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStoreRuleSlice(items), nil
}

func dbGetRule(db sqlRuleStore, id int64) (*Rule, error) {
	item, err := store.GetRule(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreRule(*item)
	return &out, nil
}

func dbGetRuleMetaByIDs(db sqlRuleStore, ids []int64) (map[int64]Rule, error) {
	items, err := store.GetRuleMetaByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStoreRuleMap(items), nil
}

func dbGetRuleProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	return store.GetRuleProtocolMapByIDs(db, ids)
}

func dbAddSite(db sqlRuleStore, s *Site) (int64, error) {
	item := toStoreSite(*s)
	return store.AddSite(db, &item)
}

func dbUpdateSite(db sqlRuleStore, s *Site) error {
	item := toStoreSite(*s)
	return store.UpdateSite(db, &item)
}

func dbDeleteSite(db sqlRuleStore, id int64) error {
	return store.DeleteSite(db, id)
}

func dbGetSites(db sqlRuleStore) ([]Site, error) {
	items, err := store.GetSites(db)
	if err != nil {
		return nil, err
	}
	return fromStoreSiteSlice(items), nil
}

func dbGetEnabledSites(db sqlRuleStore) ([]Site, error) {
	items, err := store.GetEnabledSites(db)
	if err != nil {
		return nil, err
	}
	return fromStoreSiteSlice(items), nil
}

func dbCountEnabledSites(db sqlRuleStore) (int, error) {
	return store.CountEnabledSites(db)
}

func dbGetSite(db sqlRuleStore, id int64) (*Site, error) {
	item, err := store.GetSite(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreSite(*item)
	return &out, nil
}

func dbAddRange(db sqlRuleStore, r *PortRange) (int64, error) {
	item := toStorePortRange(*r)
	return store.AddRange(db, &item)
}

func dbUpdateRange(db sqlRuleStore, r *PortRange) error {
	item := toStorePortRange(*r)
	return store.UpdateRange(db, &item)
}

func dbDeleteRange(db sqlRuleStore, id int64) error {
	return store.DeleteRange(db, id)
}

func dbGetRanges(db sqlRuleStore) ([]PortRange, error) {
	items, err := store.GetRanges(db)
	if err != nil {
		return nil, err
	}
	return fromStorePortRangeSlice(items), nil
}

func dbGetEnabledRanges(db sqlRuleStore) ([]PortRange, error) {
	items, err := store.GetEnabledRanges(db)
	if err != nil {
		return nil, err
	}
	return fromStorePortRangeSlice(items), nil
}

func dbGetEnabledRangesByIDs(db sqlRuleStore, ids []int64) ([]PortRange, error) {
	items, err := store.GetEnabledRangesByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStorePortRangeSlice(items), nil
}

func dbGetRange(db sqlRuleStore, id int64) (*PortRange, error) {
	item, err := store.GetRange(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStorePortRange(*item)
	return &out, nil
}

func dbGetRangeMetaByIDs(db sqlRuleStore, ids []int64) (map[int64]PortRange, error) {
	items, err := store.GetRangeMetaByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStorePortRangeMap(items), nil
}

func dbGetRangeProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	return store.GetRangeProtocolMapByIDs(db, ids)
}

func dbAddEgressNAT(db sqlRuleStore, item *EgressNAT) (int64, error) {
	stored := toStoreEgressNAT(*item)
	return store.AddEgressNAT(db, &stored)
}

func dbUpdateEgressNAT(db sqlRuleStore, item *EgressNAT) error {
	stored := toStoreEgressNAT(*item)
	return store.UpdateEgressNAT(db, &stored)
}

func dbDeleteEgressNAT(db sqlRuleStore, id int64) error {
	return store.DeleteEgressNAT(db, id)
}

func dbGetEgressNATs(db sqlRuleStore) ([]EgressNAT, error) {
	items, err := store.GetEgressNATs(db)
	if err != nil {
		return nil, err
	}
	return fromStoreEgressNATSlice(items), nil
}

func dbGetEnabledEgressNATs(db sqlRuleStore) ([]EgressNAT, error) {
	items, err := store.GetEnabledEgressNATs(db)
	if err != nil {
		return nil, err
	}
	return fromStoreEgressNATSlice(items), nil
}

func dbGetEgressNATsByIDs(db sqlRuleStore, ids []int64) ([]EgressNAT, error) {
	items, err := store.GetEgressNATsByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStoreEgressNATSlice(items), nil
}

func dbGetEgressNAT(db sqlRuleStore, id int64) (*EgressNAT, error) {
	item, err := store.GetEgressNAT(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreEgressNAT(*item)
	return &out, nil
}

func dbGetEgressNATProtocolMapByIDs(db sqlRuleStore, ids []int64) (map[int64]string, error) {
	values, err := store.GetEgressNATProtocolMapByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return normalizeProtocolMap(values, normalizeEgressNATProtocol), nil
}

func dbSetEgressNATEnabled(db sqlRuleStore, id int64, enabled bool) error {
	return store.SetEgressNATEnabled(db, id, enabled)
}

func dbSetRuleEnabled(db sqlRuleStore, id int64, enabled bool) error {
	return store.SetRuleEnabled(db, id, enabled)
}

func dbSetSiteEnabled(db sqlRuleStore, id int64, enabled bool) error {
	return store.SetSiteEnabled(db, id, enabled)
}

func dbSetRangeEnabled(db sqlRuleStore, id int64, enabled bool) error {
	return store.SetRangeEnabled(db, id, enabled)
}

func dbSetManagedNetworkEnabled(db sqlRuleStore, id int64, enabled bool) error {
	return store.SetManagedNetworkEnabled(db, id, enabled)
}

func dbAddIPv6Assignment(db sqlRuleStore, item *IPv6Assignment) (int64, error) {
	stored := toStoreIPv6Assignment(*item)
	return store.AddIPv6Assignment(db, &stored)
}

func dbUpdateIPv6Assignment(db sqlRuleStore, item *IPv6Assignment) error {
	stored := toStoreIPv6Assignment(*item)
	return store.UpdateIPv6Assignment(db, &stored)
}

func dbDeleteIPv6Assignment(db sqlRuleStore, id int64) error {
	return store.DeleteIPv6Assignment(db, id)
}

func dbGetIPv6Assignments(db sqlRuleStore) ([]IPv6Assignment, error) {
	items, err := store.GetIPv6Assignments(db)
	if err != nil {
		return nil, err
	}
	return fromStoreIPv6AssignmentSlice(items), nil
}

func dbGetEnabledIPv6Assignments(db sqlRuleStore) ([]IPv6Assignment, error) {
	items, err := store.GetEnabledIPv6Assignments(db)
	if err != nil {
		return nil, err
	}
	return fromStoreIPv6AssignmentSlice(items), nil
}

func dbGetIPv6Assignment(db sqlRuleStore, id int64) (*IPv6Assignment, error) {
	item, err := store.GetIPv6Assignment(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreIPv6Assignment(*item)
	return &out, nil
}

func dbAddManagedNetwork(db sqlRuleStore, item *ManagedNetwork) (int64, error) {
	stored := toStoreManagedNetwork(*item)
	return store.AddManagedNetwork(db, &stored)
}

func dbUpdateManagedNetwork(db sqlRuleStore, item *ManagedNetwork) error {
	stored := toStoreManagedNetwork(*item)
	return store.UpdateManagedNetwork(db, &stored)
}

func dbDeleteManagedNetwork(db sqlRuleStore, id int64) error {
	return store.DeleteManagedNetwork(db, id)
}

func dbGetManagedNetworks(db sqlRuleStore) ([]ManagedNetwork, error) {
	items, err := store.GetManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkSlice(items), nil
}

func dbGetEnabledManagedNetworks(db sqlRuleStore) ([]ManagedNetwork, error) {
	items, err := store.GetEnabledManagedNetworks(db)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkSlice(items), nil
}

func dbGetManagedNetworksByIDs(db sqlRuleStore, ids []int64) ([]ManagedNetwork, error) {
	items, err := store.GetManagedNetworksByIDs(db, ids)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkSlice(items), nil
}

func dbGetManagedNetwork(db sqlRuleStore, id int64) (*ManagedNetwork, error) {
	item, err := store.GetManagedNetwork(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreManagedNetwork(*item)
	return &out, nil
}

func dbAddManagedNetworkReservation(db sqlRuleStore, item *ManagedNetworkReservation) (int64, error) {
	stored := toStoreManagedNetworkReservation(*item)
	return store.AddManagedNetworkReservation(db, &stored)
}

func dbUpdateManagedNetworkReservation(db sqlRuleStore, item *ManagedNetworkReservation) error {
	stored := toStoreManagedNetworkReservation(*item)
	return store.UpdateManagedNetworkReservation(db, &stored)
}

func dbDeleteManagedNetworkReservation(db sqlRuleStore, id int64) error {
	return store.DeleteManagedNetworkReservation(db, id)
}

func dbDeleteManagedNetworkReservationsByManagedNetworkID(db sqlRuleStore, managedNetworkID int64) error {
	return store.DeleteManagedNetworkReservationsByManagedNetworkID(db, managedNetworkID)
}

func dbGetManagedNetworkReservations(db sqlRuleStore) ([]ManagedNetworkReservation, error) {
	items, err := store.GetManagedNetworkReservations(db)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkReservationSlice(items), nil
}

func dbGetManagedNetworkReservationsByManagedNetworkIDs(db sqlRuleStore, managedNetworkIDs []int64) ([]ManagedNetworkReservation, error) {
	items, err := store.GetManagedNetworkReservationsByManagedNetworkIDs(db, managedNetworkIDs)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkReservationSlice(items), nil
}

func dbGetManagedNetworkReservationCounts(db sqlRuleStore) (map[int64]int, error) {
	return store.GetManagedNetworkReservationCounts(db)
}

func dbGetManagedNetworkReservationsByManagedNetworkID(db sqlRuleStore, managedNetworkID int64) ([]ManagedNetworkReservation, error) {
	items, err := store.GetManagedNetworkReservationsByManagedNetworkID(db, managedNetworkID)
	if err != nil {
		return nil, err
	}
	return fromStoreManagedNetworkReservationSlice(items), nil
}

func dbGetManagedNetworkReservation(db sqlRuleStore, id int64) (*ManagedNetworkReservation, error) {
	item, err := store.GetManagedNetworkReservation(db, id)
	if err != nil {
		return nil, err
	}
	out := fromStoreManagedNetworkReservation(*item)
	return &out, nil
}
