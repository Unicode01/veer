package app

import (
	"database/sql"
	"fmt"
)

type effectiveNetworkPlanWarnings struct {
	DHCPv4         []string
	ManagedNetwork []string
	EgressNAT      []string
	IPv6Assignment []string
	IPv6Resolution []string
}

type effectiveNetworkPlan struct {
	ManagedNetworks         []ManagedNetwork
	Reservations            []ManagedNetworkReservation
	RuntimeManagedNetworks  []ManagedNetwork
	ExplicitIPv6Assignments []IPv6Assignment
	IPv6Assignments         []IPv6Assignment
	ExplicitEgressNATs      []EgressNAT
	SyntheticEgressNATs     []EgressNAT
	EgressNATs              []EgressNAT
	ManagedCompilation      managedNetworkRuntimeCompilation
	InterfaceSnapshot       egressNATInterfaceSnapshot
	Warnings                effectiveNetworkPlanWarnings
	IPv6LoadErr             error
	IPv6ResolutionErr       error
	RequiresInterfaceData   bool
}

type effectiveNetworkPlanLoadOptions struct {
	LoadIPv6Assignments    func(sqlRuleStore) ([]IPv6Assignment, error)
	ForceInterfaceSnapshot bool
	PluginCatalog          *PluginCatalog
}

func loadEffectiveNetworkPlan(db *sql.DB, cfg *Config, options effectiveNetworkPlanLoadOptions) (effectiveNetworkPlan, error) {
	plan := effectiveNetworkPlan{}
	if db == nil {
		return plan, fmt.Errorf("database access is required")
	}

	managedNetworks, err := dbGetManagedNetworks(db)
	if err != nil {
		return plan, fmt.Errorf("load managed networks: %w", err)
	}
	plan.ManagedNetworks = managedNetworks

	reservations, err := dbGetManagedNetworkReservations(db)
	if err != nil {
		return plan, fmt.Errorf("load managed network reservations: %w", err)
	}
	plan.Reservations = reservations

	dhcpv4Records, err := loadActivePluginDHCPv4PlanRecordsWithCatalog(db, cfg, options.PluginCatalog)
	if err != nil {
		return plan, fmt.Errorf("load plugin dhcpv4 plans: %w", err)
	}
	pluginNetworks, pluginReservations, warnings := compilePluginDHCPv4PlansAndReservationsWithWarnings(dhcpv4Records, managedNetworks)
	plan.Warnings.DHCPv4 = warnings
	plan.RuntimeManagedNetworks = append(append([]ManagedNetwork(nil), managedNetworks...), pluginNetworks...)
	plan.Reservations = append(plan.Reservations, pluginReservations...)

	explicitEgressNATs, err := dbGetEgressNATs(db)
	if err != nil {
		return plan, fmt.Errorf("load egress nats: %w", err)
	}
	egressNATRecords, err := loadActivePluginEgressNATPlanRecordsWithCatalog(db, cfg, options.PluginCatalog)
	if err != nil {
		return plan, fmt.Errorf("load plugin egress nat plans: %w", err)
	}
	ipv6Records, err := loadActivePluginIPv6AssignmentPlanRecordsWithCatalog(db, cfg, options.PluginCatalog)
	if err != nil {
		return plan, fmt.Errorf("load plugin ipv6 assignment plans: %w", err)
	}

	loadIPv6 := options.LoadIPv6Assignments
	if loadIPv6 == nil {
		loadIPv6 = dbGetIPv6Assignments
	}
	plan.ExplicitIPv6Assignments, plan.IPv6LoadErr = loadIPv6(db)

	needsInterfaceSnapshot := options.ForceInterfaceSnapshot || len(explicitEgressNATs) > 0 || len(managedNetworks) > 0 || len(egressNATRecords) > 0
	plan.RequiresInterfaceData = len(managedNetworks) > 0 || len(egressNATRecords) > 0
	if needsInterfaceSnapshot {
		plan.InterfaceSnapshot = loadEgressNATInterfaceSnapshot()
	}
	plan.ExplicitEgressNATs = normalizeEgressNATItemsWithSnapshot(explicitEgressNATs, plan.InterfaceSnapshot)
	plan.ManagedCompilation = compileManagedNetworkRuntime(
		managedNetworks,
		plan.ExplicitIPv6Assignments,
		plan.ExplicitEgressNATs,
		plan.InterfaceSnapshot.Infos,
	)
	plan.Warnings.ManagedNetwork = append([]string(nil), plan.ManagedCompilation.Warnings...)

	plan.IPv6Assignments = append([]IPv6Assignment(nil), plan.ExplicitIPv6Assignments...)
	plan.IPv6Assignments = append(plan.IPv6Assignments, plan.ManagedCompilation.IPv6Assignments...)
	if len(ipv6Records) > 0 {
		pluginIPv6Assignments, pluginWarnings := compilePluginIPv6AssignmentPlansWithWarnings(ipv6Records, plan.IPv6Assignments)
		plan.Warnings.IPv6Assignment = pluginWarnings
		plan.IPv6Assignments = append(plan.IPv6Assignments, pluginIPv6Assignments...)
	}
	if len(plan.IPv6Assignments) > 0 {
		hostIfaces, loadErr := loadIPv6AssignmentHostNetworkInterfaces()
		if loadErr != nil {
			plan.IPv6ResolutionErr = fmt.Errorf("load host interfaces for ipv6 resolution: %w", loadErr)
		} else {
			plan.IPv6Assignments, plan.Warnings.IPv6Resolution = resolveIPv6AssignmentsForCurrentHost(
				plan.IPv6Assignments,
				buildHostNetworkInterfaceMap(hostIfaces),
			)
		}
	}

	plan.SyntheticEgressNATs = append([]EgressNAT(nil), plan.ManagedCompilation.EgressNATs...)
	if len(egressNATRecords) > 0 {
		existing := append(append([]EgressNAT(nil), plan.ExplicitEgressNATs...), plan.SyntheticEgressNATs...)
		pluginEgressNATs, pluginWarnings := compilePluginEgressNATPlansWithWarnings(egressNATRecords, existing, plan.InterfaceSnapshot)
		plan.Warnings.EgressNAT = pluginWarnings
		plan.SyntheticEgressNATs = append(plan.SyntheticEgressNATs, pluginEgressNATs...)
	}
	plan.EgressNATs = append(append([]EgressNAT(nil), plan.ExplicitEgressNATs...), plan.SyntheticEgressNATs...)
	return plan, nil
}
