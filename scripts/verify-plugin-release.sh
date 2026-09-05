#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PROFILE=${1:-portable}
TMP_DIR=
PACKAGE_DIR=
MOUNTED_BPFFS=0

log() {
	printf '\n==> %s\n' "$*"
}

fail() {
	printf 'plugin release gate failed: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	if [ "$MOUNTED_BPFFS" -eq 1 ]; then
		umount /sys/fs/bpf >/dev/null 2>&1 || true
	fi
	if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
		rm -rf -- "$TMP_DIR"
	fi
	if [ -n "$PACKAGE_DIR" ] && [ -d "$PACKAGE_DIR" ]; then
		case "$PACKAGE_DIR" in
			"$ROOT_DIR/dist/"*) rm -rf -- "$PACKAGE_DIR" ;;
		esac
	fi
}

ensure_bpffs() {
	mkdir -p /sys/fs/bpf
	if mountpoint -q /sys/fs/bpf; then
		return
	fi
	mount -t bpf bpf /sys/fs/bpf
	MOUNTED_BPFFS=1
}

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_linux_root() {
	[ "$(uname -s)" = "Linux" ] || fail "$PROFILE requires Linux"
	[ "$(id -u)" -eq 0 ] || fail "$PROFILE requires root"
	for command_name in ip clang unshare ping awk sort; do
		require_command "$command_name"
	done
}

prepare_portable_ebpf() {
	if [ "$(go env GOOS)" = "linux" ]; then
		log "build core and bundled plugin eBPF objects"
		sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
		return
	fi

	log "verify prebuilt plugin eBPF objects on non-Linux host"
	for object_path in \
		"$ROOT_DIR/plugins/packet_observer/packet_observer.o" \
		"$ROOT_DIR/plugins/pppoe_client/pppoe_tunnel.o"
	do
		[ -f "$object_path" ] || fail "non-Linux portable gate requires prebuilt object: $object_path"
	done
}

new_temp_dir() {
	if [ -z "$TMP_DIR" ]; then
		TMP_DIR=$(mktemp -d "$ROOT_DIR/.veer-plugin-release.XXXXXX")
	fi
}

run_no_skips() {
	label=$1
	log_file=$2
	shift 2
	log "$label"
	if ! "$@" >"$log_file" 2>&1; then
		cat "$log_file"
		fail "$label"
	fi
	cat "$log_file"
	if grep -F -- '--- SKIP:' "$log_file" >/dev/null 2>&1; then
		printf '\nSkipped tests rejected by the release gate:\n' >&2
		grep -F -- '--- SKIP:' "$log_file" >&2 || true
		fail "$label reported a skipped test"
	fi
}

require_test_pass() {
	log_file=$1
	test_name=$2
	grep -F -- "--- PASS: $test_name" "$log_file" >/dev/null 2>&1 || \
		fail "required test did not pass: $test_name"
}

validate_positive_integer() {
	name=$1
	value=$2
	case "$value" in
		''|*[!0-9]*) fail "$name must be a positive integer" ;;
	esac
	[ "$value" -gt 0 ] || fail "$name must be a positive integer"
}

validate_ratio() {
	name=$1
	value=$2
	awk -v value="$value" 'BEGIN { if (value !~ /^[0-9]+([.][0-9]+)?$/ || value <= 0 || value > 1) exit 1 }' || \
		fail "$name must be greater than 0 and no greater than 1"
}

median_file() {
	sort -n "$1" | awk '{ values[NR] = $1 } END { if (NR == 0) exit 1; if (NR % 2) print values[(NR + 1) / 2]; else print (values[NR / 2] + values[NR / 2 + 1]) / 2 }'
}

assert_minimum() {
	label=$1
	value=$2
	minimum=$3
	awk -v value="$value" -v minimum="$minimum" 'BEGIN { if (value < minimum) exit 1 }' || \
		fail "$label median paired ratio $value is below $minimum"
}

run_portable() {
	for command_name in go node npm npx python3 sh tar cmp govulncheck; do
		require_command "$command_name"
	done
	new_temp_dir

	log "Go module integrity"
	(cd "$ROOT_DIR" && go mod verify && go mod tidy -diff)

	prepare_portable_ebpf

	log "deployment platform scripts"
	sh "$ROOT_DIR/scripts/verify-platform-support.sh"
	python3 "$ROOT_DIR/scripts/verify-deploy-config-policy.py"
	sh "$ROOT_DIR/scripts/clean-dev-artifacts.sh" --dry-run

	log "build Veer conformance binary"
	verify_binary="$TMP_DIR/veer-plugin-verify"
	case "$(go env GOOS)" in
		windows) verify_binary="${verify_binary}.exe" ;;
	esac
	(cd "$ROOT_DIR" && go build -trimpath -o "$verify_binary" .)

	log "Go tests"
	(cd "$ROOT_DIR" && go test ./... -count=1)

	log "Go race tests"
	(cd "$ROOT_DIR" && go test -race ./... -count=1 -timeout=15m)

	log "Go vet"
	(cd "$ROOT_DIR" && go vet ./...)

	log "WebUI Node tests"
	(cd "$ROOT_DIR" && node --test internal/app/web_test/*.test.js)

	log "WebUI browser tests"
	(cd "$ROOT_DIR" && npm run test:web:e2e)

	log "plugin SDK Node tests"
	(cd "$ROOT_DIR" && node --test sdk/plugin/test-host.test.cjs)

	log "PPPoE control-plane self-test"
	(cd "$ROOT_DIR" && node plugins/pppoe_client/test-control-node.js)

	log "plugin SDK TypeScript declarations"
	(cd "$ROOT_DIR" && npx --yes --package typescript@5.9.3 tsc \
		--noEmit --strict --skipLibCheck false --target ES2022 --moduleResolution node \
		sdk/plugin/control.d.ts sdk/plugin/methods.d.ts sdk/plugin/webui.d.ts sdk/plugin/test-host.d.ts)

	log "SDK contract"
	"$verify_binary" plugin contract --check "$ROOT_DIR/sdk/plugin/api-contract.json"

	log "deterministic plugin SDK package"
	sdk_archive_a="$TMP_DIR/veer-plugin-sdk-a.tar.gz"
	sdk_archive_b="$TMP_DIR/veer-plugin-sdk-b.tar.gz"
	VEER_PLUGIN_SDK_OUTPUT="$sdk_archive_a" sh "$ROOT_DIR/scripts/package-plugin-sdk.sh"
	VEER_PLUGIN_SDK_OUTPUT="$sdk_archive_b" sh "$ROOT_DIR/scripts/package-plugin-sdk.sh"
	cmp "$sdk_archive_a" "$sdk_archive_b" || fail "plugin SDK package is not deterministic"
	sdk_extract="$TMP_DIR/plugin-sdk-extract"
	mkdir -p "$sdk_extract"
	tar -xzf "$sdk_archive_a" -C "$sdk_extract"
	test -f "$sdk_extract/veer-plugin-sdk/sdk-manifest.json" || fail "plugin SDK manifest is missing"
	test -f "$sdk_extract/veer-plugin-sdk/sdk/plugin/control.d.ts" || fail "plugin SDK control declarations are missing"
	test -f "$sdk_extract/veer-plugin-sdk/sdk/plugin/test-host.cjs" || fail "plugin SDK test host is missing"
	test -f "$sdk_extract/veer-plugin-sdk/plugins/include/veer_plugin_helpers.h" || fail "plugin SDK eBPF helper is missing"
	test -f "$sdk_extract/veer-plugin-sdk/sdk/plugin/templates/plugin-ci.yml" || fail "plugin SDK CI template is missing"
	scaffold="$TMP_DIR/plugin-sdk-scaffold"
	"$verify_binary" plugin init --id release_gate --kind pipeline --directory "$scaffold" \
		--sdk-include "$sdk_extract/veer-plugin-sdk/plugins/include"
	VEER_BIN="$verify_binary" \
		sh "$sdk_extract/veer-plugin-sdk/sdk/plugin/ci/verify.sh" "$scaffold"
	prebuilt_scaffold="$TMP_DIR/plugin-sdk-prebuilt-scaffold"
	cp -R "$scaffold" "$prebuilt_scaffold"
	rm -f "$prebuilt_scaffold/main.bpf.c"
	VEER_BIN="$verify_binary" \
		sh "$sdk_extract/veer-plugin-sdk/sdk/plugin/ci/verify.sh" "$prebuilt_scaffold"
	control_scaffold="$TMP_DIR/plugin-sdk-control-scaffold"
	"$verify_binary" plugin init --id release_control --kind control --directory "$control_scaffold"
	VEER_BIN="$verify_binary" \
		sh "$sdk_extract/veer-plugin-sdk/sdk/plugin/ci/verify.sh" "$control_scaffold"
	ui_scaffold="$TMP_DIR/plugin-sdk-ui-scaffold"
	"$verify_binary" plugin init --id release_ui --kind ui --directory "$ui_scaffold"
	VEER_BIN="$verify_binary" \
		sh "$sdk_extract/veer-plugin-sdk/sdk/plugin/ci/verify.sh" "$ui_scaffold"

	for target_arch in amd64 arm64; do
		log "plugin conformance for linux/$target_arch"
		VEER_PLUGIN_VERIFY_BINARY="$verify_binary" \
		VEER_PLUGIN_VERIFY_OS=linux \
		VEER_PLUGIN_VERIFY_ARCH="$target_arch" \
		VEER_PLUGIN_VERIFY_KERNEL=6.6.0 \
			sh "$ROOT_DIR/scripts/verify-plugin-manifests.sh"
	done

	log "stable plugin package round trip"
	PACKAGE_DIR="$ROOT_DIR/dist/.veer-plugin-release-$$"
	VEER_PLUGIN_PACKAGE_SKIP_BUILD=1 \
	VEER_PLUGIN_PACKAGE_DIR="$PACKAGE_DIR" \
		sh "$ROOT_DIR/scripts/package-plugins.sh"

	log "reachable vulnerability scan"
	(cd "$ROOT_DIR" && govulncheck ./...)

	fuzz_seconds=${VEER_PLUGIN_RELEASE_FUZZ_SECONDS:-10}
	validate_positive_integer VEER_PLUGIN_RELEASE_FUZZ_SECONDS "$fuzz_seconds"
	for fuzz_target in \
		FuzzNormalizePluginPackageEntryName \
		FuzzExtractPluginPackageArchive \
		FuzzPluginManifestDecodeAndNormalize \
		FuzzPluginHostFrameDecode \
		FuzzDecodePluginBlobHeader \
		FuzzNormalizePluginOperationJSONAndStatus \
		FuzzPluginOperationSecretEnvelope
	do
		log "fuzz $fuzz_target (${fuzz_seconds}s)"
		(cd "$ROOT_DIR" && GOMAXPROCS=2 go test ./internal/app -run '^$' \
			-fuzz="^${fuzz_target}$" -fuzztime="${fuzz_seconds}s" -parallel=2)
	done
}

run_privileged() {
	require_linux_root
	require_command nft
	require_command tc
	require_command tcpdump
	new_temp_dir
	log "build eBPF objects for privileged integration"
	sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
	log "build privileged integration binary"
	privileged_binary="$TMP_DIR/veer-plugin-privileged.test"
	go test -c -o "$privileged_binary" ./internal/app

	privileged_log="$TMP_DIR/privileged.log"
	privileged_pattern='^(TestPluginHostSeccompFilterRejectsForeignABIAndBlockedSyscalls|TestPluginHostLinuxSandboxIdentityAndCgroup|TestPluginHostLinuxSandboxSupportsConcurrentHosts|TestPluginHostLinuxSandboxEnforcementProbe|TestPluginHostLinuxChrootFallbackEnforcementProbe|TestPluginHostIsolationContainsMemoryExhaustion|TestPluginHostIsolationLoadsRelativeControlModulesInMainAndWorker|TestPluginHostIsolationBrokersTypedServiceDiscoveryAndCall|TestCleanupOrphanPluginHostCgroups|TestCleanupOrphanPluginHostFilesystemRoots|TestLinuxPluginScopedNamespaceNetworkAPIs|TestEgressNATTCActiveTCPRefreshesBothFlowEntries|TestEgressNATTCFullConeSYNRetryKeepsNATPort|TestPlugin(NetPolicyProviderLinuxIntegration|NetPolicyTransactionsLinuxIntegration|MultipathRouteLinuxIntegration|NamespaceTunTapLinuxIntegration|NamespaceTunTapCrashRecoveryLinuxIntegration|NetTransactionCrashRecoveryLinuxIntegration|WANCoreLinuxIntegration|VToLocalLinuxIntegration|LANCoreLinuxIntegration|ActionApplyPersistsAndRepairsLinuxIntegration|LANCoreResolvesWANCoreStatusLinuxIntegration|ControlNetEnsureVethRejectsMismatchedExistingPeersLinuxIntegration|ControlNetEnsureMacvlanLinuxIntegration|ControlNetSetGSOLinuxIntegration|ControlNetAddrReplaceIdempotentLinuxIntegration|DataplaneRuntimeAttachesTCObservePlugin|IPv6AssignmentPlanLinuxIntegration|LANCoreGeneratedEgressNATTCIntegration|LANCoreResolvesWANCoreEgressNATTCIntegration)|TestKernelPluginPipelineRuntime.*|TestKernelXDPPluginPipelineChainHotUpdateAndConflict|TestKernelXDPPluginPipelineRecoversOrphanAfterSIGKILL|TestKernelNetfilterPlugin(PipelineIntegration|PriorityIntegration|NamespaceRecreateIntegration|InitialMissingNamespaceRecoversIntegration)|TestOrderedKernelRuntimeChainsXDPIntoTCPlugin)$'
	env_command=$(command -v env)
	set -- \
		"$env_command" \
		"HOME=${HOME:-/root}" \
		"PATH=$PATH" \
		"GOPATH=$(go env GOPATH)" \
		"GOMODCACHE=$(go env GOMODCACHE)" \
		"GOCACHE=$(go env GOCACHE)" \
		FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 \
		FORWARD_RUN_PLUGIN_DATAPLANE_TEST=1 \
		FORWARD_RUN_PLUGIN_PIPELINE_TEST=1 \
		FORWARD_RUN_PLUGIN_IPV6_PLAN_TEST=1 \
		FORWARD_RUN_EGRESS_NAT_TEST=1 \
		VEER_RUN_PLUGIN_NETNS_SCOPED_TESTS=1 \
		VEER_RUN_XDP_PLUGIN_TESTS=1 \
		VEER_RUN_NETFILTER_PLUGIN_TEST=1 \
		VEER_PLUGIN_OOM_TEST=1 \
		"$privileged_binary" \
		-test.v -test.run "$privileged_pattern" -test.count=1 -test.timeout=30m
	if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		set -- systemd-run --quiet --wait --pipe --collect \
			--property=Delegate=yes \
			--property=Type=exec \
			--property="WorkingDirectory=$ROOT_DIR" \
			"$@"
	fi
	run_no_skips "privileged plugin integration" "$privileged_log" "$@"

	for required_test in \
		TestPluginHostSeccompFilterRejectsForeignABIAndBlockedSyscalls \
		TestPluginHostLinuxSandboxIdentityAndCgroup \
		TestPluginHostLinuxSandboxSupportsConcurrentHosts \
		TestPluginHostLinuxSandboxEnforcementProbe \
		TestPluginHostLinuxChrootFallbackEnforcementProbe \
		TestCleanupOrphanPluginHostFilesystemRoots \
		TestPluginHostIsolationContainsMemoryExhaustion \
		TestPluginHostIsolationLoadsRelativeControlModulesInMainAndWorker \
		TestPluginHostIsolationBrokersTypedServiceDiscoveryAndCall \
		TestPluginNetPolicyTransactionsLinuxIntegration \
		TestPluginNamespaceTunTapCrashRecoveryLinuxIntegration \
		TestPluginNetTransactionCrashRecoveryLinuxIntegration \
		TestPluginControlNetAddrReplaceIdempotentLinuxIntegration \
		TestPluginWANCoreLinuxIntegration \
		TestPluginVToLocalLinuxIntegration \
		TestPluginLANCoreLinuxIntegration \
		TestPluginDataplaneRuntimeAttachesTCObservePlugin \
		TestPluginIPv6AssignmentPlanLinuxIntegration \
		TestEgressNATTCActiveTCPRefreshesBothFlowEntries \
		TestEgressNATTCFullConeSYNRetryKeepsNATPort \
		TestPluginLANCoreGeneratedEgressNATTCIntegration \
		TestPluginLANCoreResolvesWANCoreEgressNATTCIntegration \
		TestKernelPluginPipelineRuntimeChainsPreForwardPlugin \
		TestKernelPluginPipelineRuntimePreservesDeclaredMapAcrossObjectUpgrade \
		TestKernelPluginPipelineRuntimeMigratesStateMapAndRollsBackToPreservedSource \
		TestKernelPluginPipelineRuntimeIPv6PostApplyForwardsTraffic \
		TestKernelPluginPipelineRuntimeNoRulePreCorePluginCanDropTraffic \
		TestKernelPluginPipelineRuntimeNoRulePreCorePluginCanRedirectBetweenInterfaces \
		TestKernelPluginPipelineRuntimeChainsPostReplyPlugin \
		TestKernelPluginPipelineRuntimePersistsReplyFlowSnapshotState \
		TestKernelXDPPluginPipelineChainHotUpdateAndConflict \
		TestKernelXDPPluginPipelineRecoversOrphanAfterSIGKILL \
		TestKernelNetfilterPluginPipelineIntegration \
		TestKernelNetfilterPluginPriorityIntegration \
		TestKernelNetfilterPluginNamespaceRecreateIntegration \
		TestKernelNetfilterPluginInitialMissingNamespaceRecoversIntegration \
		TestOrderedKernelRuntimeChainsXDPIntoTCPlugin
	do
		require_test_pass "$privileged_log" "$required_test"
	done
	pppoe_blackbox_binary="$TMP_DIR/veer-pppoe-blackbox"
	(cd "$ROOT_DIR" && go build -trimpath -o "$pppoe_blackbox_binary" .)

	log "PPPoE Linux blackbox: IPv4 data and manual redial"
	VEER_BINARY="$pppoe_blackbox_binary" \
	VEER_PPPOE_BLACKBOX_SECONDS=8 \
		sh "$ROOT_DIR/plugins/pppoe_client/test-blackbox-linux.sh"

	log "PPPoE Linux blackbox: IPv6 data"
	VEER_BINARY="$pppoe_blackbox_binary" \
	VEER_PPPOE_BLACKBOX_SECONDS=4 \
	VEER_PPPOE_BLACKBOX_TEST_IPV6=1 \
		sh "$ROOT_DIR/plugins/pppoe_client/test-blackbox-linux.sh"

	log "PPPoE Linux blackbox: timer fence"
	VEER_BINARY="$pppoe_blackbox_binary" \
	VEER_PPPOE_BLACKBOX_RUN_IPERF=0 \
	VEER_PPPOE_BLACKBOX_TEST_TIMER_FENCE=1 \
		sh "$ROOT_DIR/plugins/pppoe_client/test-blackbox-linux.sh"

	log "PPPoE Linux blackbox: automatic redial"
	VEER_BINARY="$pppoe_blackbox_binary" \
	VEER_PPPOE_BLACKBOX_RUN_IPERF=0 \
	VEER_PPPOE_BLACKBOX_TEST_AUTO_REDIAL=1 \
		sh "$ROOT_DIR/plugins/pppoe_client/test-blackbox-linux.sh"
}

run_flow_churn() {
	require_linux_root
	for command_name in bridge mount mountpoint tc; do
		require_command "$command_name"
	done
	ensure_bpffs
	new_temp_dir

	flow_churn_binary=${VEER_CORE_TEST_BINARY:-}
	if [ -z "$flow_churn_binary" ]; then
		log "build eBPF objects for flow churn integration"
		sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
		log "build flow churn integration binary"
		flow_churn_binary="$TMP_DIR/veer-flow-churn.test"
		go test -c -o "$flow_churn_binary" ./internal/app
	fi

	flow_churn_log="$TMP_DIR/flow-churn.log"
	flow_churn_pattern='^(TestCollectPreparedKernelRuleFlowPurgeTargets.*|TestKernelFlowPurgeRetryState.*|TestKernelFlowMatchesPurgeTargetsScopesInterfaceAndRevision|TestKernelFlowMatchesInterfaceScopedPurgeTargetRejectsCoveredAndInvalidTargets|TestKernelFlowPurgeSessionIdentityRequiresFullNATAndNonzeroSession|TestPurgeKernelFlowsForTargetsScopesTransparentBridgeMemberWithoutDeletingParent|TestPurgeKernelFlowsForTargetsScopesInterfaceAcrossTCBanksAndFamilies|TestPurgeKernelFlowsForTargetsHandlesMixedScopedAndFullRevisionTargets|TestPurgeKernelFlowsForTargetsDoesNotPairZeroSessionFullNATEntries|TestTCRuleMutationMapIDFromFDInfo|TestTCKernelRuleMutationEstablishedTCPConnection|TestTCKernelRuleMutationBridgeMemberChurnKeepsEstablishedTCPConnection)$'
	run_no_skips "kernel flow purge and bridge churn integration" "$flow_churn_log" \
		env \
		FORWARD_RUN_TC_RULE_MUTATION_TEST=1 \
		"$flow_churn_binary" \
		-test.v -test.run "$flow_churn_pattern" -test.count=1 -test.timeout=10m

	for required_test in \
		TestPurgeKernelFlowsForTargetsScopesTransparentBridgeMemberWithoutDeletingParent \
		TestPurgeKernelFlowsForTargetsScopesInterfaceAcrossTCBanksAndFamilies \
		TestPurgeKernelFlowsForTargetsHandlesMixedScopedAndFullRevisionTargets \
		TestPurgeKernelFlowsForTargetsDoesNotPairZeroSessionFullNATEntries \
		TestTCKernelRuleMutationEstablishedTCPConnection/backend_port_update_breaks_connection \
		TestTCKernelRuleMutationEstablishedTCPConnection/delete_rule_breaks_connection \
		TestTCKernelRuleMutationBridgeMemberChurnKeepsEstablishedTCPConnection
	do
		require_test_pass "$flow_churn_log" "$required_test"
	done
}

run_core_dataplane() {
	require_linux_root
	for command_name in bridge mount mountpoint tc; do
		require_command "$command_name"
	done
	ensure_bpffs
	new_temp_dir
	core_binary=${VEER_CORE_TEST_BINARY:-}
	if [ -z "$core_binary" ]; then
		sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
		core_binary="$TMP_DIR/veer-core.test"
		go test -c -o "$core_binary" ./internal/app
	fi
	core_tests='TestLoadEmbeddedKernelCollectionsSmoke TestKernelPreparersRejectPortTruncation TestTCKernelIPv6Integration TestTCKernelIPv6RangeIntegration TestXDPKernelIPv4FullNATIntegration TestXDPKernelIPv4FullNATTransparentCoexists TestXDPKernelIPv4FullNATToggleDisableReenableRestoresConnectivity TestXDPKernelIPv4FullNATDeleteRecreateRestoresConnectivity TestXDPKernelIPv6Integration TestTCKernelTransparentRejectsACKOnlyNewSession TestXDPKernelTransparentRejectsACKOnlyNewSession TestEgressNATTCIntegration TestEgressNATXDPIntegration TestEgressNATUDPMappingRespectsNATType TestEgressNATKernelWildcardForwardCoexists'
	core_pattern=$(printf '%s' "$core_tests" | tr ' ' '|')
	core_log="$TMP_DIR/core-dataplane.log"
	run_no_skips "core TC/XDP, IPv4/IPv6, NAT and session guard matrix" "$core_log" \
		env FORWARD_RUN_KERNEL_LOAD_SMOKE=1 FORWARD_RUN_TC_IPV6_TEST=1 \
		FORWARD_RUN_XDP_FULLNAT_TEST=1 FORWARD_RUN_XDP_IPV6_TEST=1 \
		FORWARD_RUN_TCP_SESSION_GUARD_TEST=1 FORWARD_RUN_EGRESS_NAT_TEST=1 \
		FORWARD_RUN_EGRESS_NAT_XDP_TEST=1 \
		"$core_binary" -test.v -test.run "^($core_pattern)$" -test.count=1 -test.timeout=20m
	for required_test in $core_tests; do
		require_test_pass "$core_log" "$required_test"
	done
}

run_stability() {
	require_linux_root
	new_temp_dir
	seconds=${VEER_PLUGIN_RELEASE_STABILITY_SECONDS:-120}
	validate_positive_integer VEER_PLUGIN_RELEASE_STABILITY_SECONDS "$seconds"
	[ "$seconds" -ge 120 ] || fail "release stability duration must be at least 120 seconds"

	log "build eBPF objects for stability gate"
	sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
	stability_log="$TMP_DIR/stability.log"
	run_no_skips "TC plugin long-flow and new-flow stability (${seconds}s)" "$stability_log" \
		env \
		FORWARD_RUN_PLUGIN_STABILITY_TEST=1 \
		FORWARD_PLUGIN_STABILITY_SECONDS="$seconds" \
		FORWARD_PLUGIN_STABILITY_LONG_CONNECTIONS=64 \
		FORWARD_PLUGIN_STABILITY_LONG_ACTIVE=16 \
		FORWARD_PLUGIN_STABILITY_NEW_CONNECTIONS=32 \
		FORWARD_PLUGIN_STABILITY_NEW_CONCURRENCY=8 \
		FORWARD_PLUGIN_STABILITY_NEW_INTERVAL_MS=500 \
		FORWARD_PERF_BYTES_PER_CONN=1048576 \
		FORWARD_PERF_WARMUP_BYTES_PER_CONN=65536 \
		FORWARD_PERF_IO_CHUNK_BYTES=16384 \
		go test -v ./internal/app -run '^TestDataplanePluginPipelineStability$' -count=1 -timeout=20m
	require_test_pass "$stability_log" TestDataplanePluginPipelineStability
}

record_tc_sample() {
	profile=$1
	plugins_enabled=$2
	plugin_count=$3
	workload=$4
	result_file="$TMP_DIR/tc-${profile}.values"
	log_file="$TMP_DIR/tc-${profile}-${sample_round}.log"
	pipeline_enabled=0
	if [ "$plugin_count" -gt 0 ]; then
		pipeline_enabled=1
	fi

	if ! env \
		FORWARD_RUN_PERF_TEST=1 \
		FORWARD_PERF_BINARY="$perf_binary" \
		FORWARD_PERF_PLUGIN_SOURCE_DIR="$ROOT_DIR/plugins/packet_observer" \
		FORWARD_PERF_MODES=tc \
		FORWARD_PERF_PROTOCOL=tcp \
		FORWARD_PERF_TCP_MODE=echo \
		FORWARD_PERF_CONNECTIONS=64 \
		FORWARD_PERF_CONCURRENCY=16 \
		FORWARD_PERF_BYTES_PER_CONN=1048576 \
		FORWARD_PERF_IO_CHUNK_BYTES=16384 \
		FORWARD_PERF_WARMUP_CONNECTIONS=8 \
		FORWARD_PERF_WARMUP_BYTES_PER_CONN=65536 \
		FORWARD_PERF_STEADY_SECONDS="$perf_steady_seconds" \
		FORWARD_PERF_PLUGINS_ENABLED="$plugins_enabled" \
		FORWARD_PERF_PLUGIN_PIPELINE="$pipeline_enabled" \
		FORWARD_PERF_PLUGIN_PIPELINE_COUNT="$plugin_count" \
		FORWARD_PERF_PLUGIN_WORKLOAD="$workload" \
		go test -v ./internal/app -run '^TestDataplanePerfMatrix$' -count=1 -timeout=10m \
		>"$log_file" 2>&1
	then
		cat "$log_file"
		fail "TC performance sample $profile/$sample_round"
	fi
	if grep -F -- '--- SKIP:' "$log_file" >/dev/null 2>&1; then
		cat "$log_file"
		fail "TC performance sample $profile/$sample_round was skipped"
	fi
	value=$(sed -n 's/.*tc payload=\([0-9][0-9.]*\) MiB\/s.*/\1/p' "$log_file" | tail -n 1)
	[ -n "$value" ] || {
		cat "$log_file"
		fail "TC performance sample $profile/$sample_round has no throughput result"
	}
	printf '%s\n' "$value" >>"$result_file"
	printf 'TC sample profile=%s round=%s throughput=%s MiB/s\n' "$profile" "$sample_round" "$value"
}

record_tc_pair() {
	pair_profile=$1
	pair_plugins_enabled=$2
	pair_plugin_count=$3
	pair_workload=$4
	pair_baseline_profile="${pair_profile}_baseline"

	if [ $(((sample_round + pair_index) % 2)) -eq 0 ]; then
		record_tc_sample "$pair_baseline_profile" 0 0 noop
		record_tc_sample "$pair_profile" "$pair_plugins_enabled" "$pair_plugin_count" "$pair_workload"
	else
		record_tc_sample "$pair_profile" "$pair_plugins_enabled" "$pair_plugin_count" "$pair_workload"
		record_tc_sample "$pair_baseline_profile" 0 0 noop
	fi

	pair_baseline=$(tail -n 1 "$TMP_DIR/tc-${pair_baseline_profile}.values")
	pair_value=$(tail -n 1 "$TMP_DIR/tc-${pair_profile}.values")
	pair_ratio=$(awk -v value="$pair_value" -v baseline="$pair_baseline" 'BEGIN { printf "%.6f", value / baseline }')
	printf '%s\n' "$pair_ratio" >>"$TMP_DIR/tc-${pair_profile}.ratios"
	printf 'TC pair profile=%s round=%s baseline=%s throughput=%s ratio=%s\n' \
		"$pair_profile" "$sample_round" "$pair_baseline" "$pair_value" "$pair_ratio"
	pair_index=$((pair_index + 1))
}

run_tc_performance() {
	for profile in enabled noop observer firewall noop2 noop4 noop8; do
		: >"$TMP_DIR/tc-${profile}.values"
		: >"$TMP_DIR/tc-${profile}_baseline.values"
		: >"$TMP_DIR/tc-${profile}.ratios"
	done

	sample_round=1
	while [ "$sample_round" -le "$perf_samples" ]; do
		log "TC plugin performance round $sample_round/$perf_samples"
		pair_index=0
		if [ $((sample_round % 2)) -eq 1 ]; then
			record_tc_pair enabled 1 0 noop
			record_tc_pair noop 1 1 noop
			record_tc_pair observer 1 1 observer
			record_tc_pair firewall 1 1 firewall
			record_tc_pair noop2 1 2 noop
			record_tc_pair noop4 1 4 noop
			record_tc_pair noop8 1 8 noop
		else
			record_tc_pair noop8 1 8 noop
			record_tc_pair noop4 1 4 noop
			record_tc_pair noop2 1 2 noop
			record_tc_pair firewall 1 1 firewall
			record_tc_pair observer 1 1 observer
			record_tc_pair noop 1 1 noop
			record_tc_pair enabled 1 0 noop
		fi
		sample_round=$((sample_round + 1))
	done

	printf '\nTC paired performance medians:\n'
	for profile in enabled noop observer firewall noop2 noop4 noop8; do
		baseline=$(median_file "$TMP_DIR/tc-${profile}_baseline.values") || fail "calculate TC $profile baseline median"
		value=$(median_file "$TMP_DIR/tc-${profile}.values") || fail "calculate TC $profile median"
		ratio=$(median_file "$TMP_DIR/tc-${profile}.ratios") || fail "calculate TC $profile paired ratio median"
		printf '  %-9s baseline=%10s MiB/s  profile=%10s MiB/s  paired_ratio=%s\n' "$profile" "$baseline" "$value" "$ratio"
		case "$profile" in
			enabled) assert_minimum "TC enabled without hooks" "$ratio" "$perf_nohook_ratio" ;;
			noop|observer|firewall) assert_minimum "TC $profile" "$ratio" "$perf_hook_ratio" ;;
			*) assert_minimum "TC $profile" "$ratio" "$perf_curve_ratio" ;;
		esac
	done
}

run_xdp_performance() {
	xdp_log="$TMP_DIR/xdp-benchmark.log"
	run_no_skips "XDP plugin dispatcher benchmark" "$xdp_log" \
		env VEER_RUN_XDP_PLUGIN_BENCH=1 \
		go test ./internal/app -run '^$' -bench '^BenchmarkKernelXDPPluginChain$' -benchtime=1s -count=3 -timeout=10m

	awk '
		/^BenchmarkKernelXDPPluginChain\// {
			name = $1
			sub(/^.*\//, "", name)
			sub(/-[0-9]+$/, "", name)
			for (i = 1; i < NF; i++) if ($(i + 1) == "ns/op") print $i >> (out "/xdp-" name ".values")
		}
	' out="$TMP_DIR" "$xdp_log"

	plain=$(median_file "$TMP_DIR/xdp-plain_pass.values") || fail "missing XDP plain benchmark"
	zero=$(median_file "$TMP_DIR/xdp-dispatcher_0_plugins.values") || fail "missing XDP zero-hook benchmark"
	zero_overhead=$(awk -v zero="$zero" -v plain="$plain" 'BEGIN { printf "%.4f", zero - plain }')
	printf '\nXDP performance medians: plain=%s ns dispatcher0=%s ns overhead=%s ns\n' "$plain" "$zero" "$zero_overhead"
	awk -v overhead="$zero_overhead" -v maximum="$xdp_zero_max_ns" 'BEGIN { if (overhead > maximum) exit 1 }' || \
		fail "XDP zero-hook dispatcher overhead ${zero_overhead}ns exceeds ${xdp_zero_max_ns}ns"

	for count in 1 2 4 8; do
		value=$(median_file "$TMP_DIR/xdp-dispatcher_${count}_plugins.values") || fail "missing XDP ${count}-hook benchmark"
		per_hook=$(awk -v value="$value" -v zero="$zero" -v count="$count" 'BEGIN { printf "%.4f", (value - zero) / count }')
		printf '  hooks=%s median=%s ns incremental=%s ns/hook\n' "$count" "$value" "$per_hook"
		awk -v value="$per_hook" -v maximum="$xdp_hook_max_ns" 'BEGIN { if (value > maximum) exit 1 }' || \
			fail "XDP ${count}-hook incremental cost ${per_hook}ns exceeds ${xdp_hook_max_ns}ns/hook"
	done
}

run_netfilter_performance() {
	netfilter_log="$TMP_DIR/netfilter-performance.log"
	run_no_skips "Netfilter plugin performance" "$netfilter_log" \
		env \
		VEER_RUN_NETFILTER_PLUGIN_TEST=1 \
		VEER_RUN_NETFILTER_PLUGIN_PERF=1 \
		VEER_NETFILTER_PLUGIN_MIN_RATIO="$netfilter_hook_ratio" \
		go test -v ./internal/app -run '^TestKernelNetfilterPluginPerformance$' -count=1 -timeout=10m
	require_test_pass "$netfilter_log" TestKernelNetfilterPluginPerformance
}

run_performance() {
	require_linux_root
	require_command iperf3
	new_temp_dir
	perf_samples=${VEER_PLUGIN_RELEASE_PERF_SAMPLES:-3}
	perf_steady_seconds=${VEER_PLUGIN_RELEASE_PERF_SECONDS:-6}
	perf_nohook_ratio=${VEER_PLUGIN_RELEASE_PERF_NOHOOK_RATIO:-0.95}
	perf_hook_ratio=${VEER_PLUGIN_RELEASE_PERF_HOOK_RATIO:-0.90}
	perf_curve_ratio=${VEER_PLUGIN_RELEASE_PERF_CURVE_RATIO:-0.80}
	xdp_zero_max_ns=${VEER_PLUGIN_RELEASE_XDP_ZERO_MAX_NS:-30}
	xdp_hook_max_ns=${VEER_PLUGIN_RELEASE_XDP_HOOK_MAX_NS:-75}
	netfilter_hook_ratio=${VEER_PLUGIN_RELEASE_NETFILTER_RATIO:-0.80}
	validate_positive_integer VEER_PLUGIN_RELEASE_PERF_SAMPLES "$perf_samples"
	validate_positive_integer VEER_PLUGIN_RELEASE_PERF_SECONDS "$perf_steady_seconds"
	validate_ratio VEER_PLUGIN_RELEASE_NETFILTER_RATIO "$netfilter_hook_ratio"
	[ "$perf_samples" -ge 3 ] || fail "performance gate requires at least three samples"
	[ $((perf_samples % 2)) -eq 1 ] || fail "performance sample count must be odd"
	[ "$perf_steady_seconds" -ge 5 ] || fail "performance sample duration must be at least five seconds"

	log "build eBPF objects and performance binary"
	sh "$ROOT_DIR/scripts/build-all-ebpf.sh"
	perf_binary="$TMP_DIR/veer-perf"
	(cd "$ROOT_DIR" && go build -trimpath -o "$perf_binary" .)

	run_tc_performance
	run_xdp_performance
	run_netfilter_performance
}

case "$PROFILE" in
	portable)
		run_portable
		;;
	privileged)
		run_privileged
		;;
	flow-churn)
		run_flow_churn
		;;
	core-dataplane)
		run_core_dataplane
		;;
	stability)
		run_stability
		;;
	performance)
		run_performance
		;;
	all)
		run_portable
		run_privileged
		run_flow_churn
		run_core_dataplane
		run_stability
		run_performance
		;;
	*)
		printf 'usage: %s [portable|privileged|flow-churn|core-dataplane|stability|performance|all]\n' "$0" >&2
		exit 2
		;;
esac

log "plugin release gate passed: $PROFILE"
