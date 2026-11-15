#!/usr/bin/env sh
# Requires root, matching headers, clang, pahole, kmod and network test tools.
#
# usage: verify-kernel-module.sh [PHASE...]
# Without arguments every phase runs in order. CI runs one phase per workflow
# step, because GitHub keeps each step's start and end time even when a
# runner stops responding and its log is lost. VEER_KMOD_WORK then keeps the
# binaries between the steps, and the module stays loaded from the load
# phase to the unload phase.
#
# Every step has a time limit well inside the CI job's. A step that runs past
# it is shown with its processes, their kernel stacks and the kernel log, and
# then stopped; one that cannot be killed (stuck in the kernel) is abandoned.
# Steps write to a file that is streamed here, so a stuck process never holds
# the CI log open, and the job fails with its log instead of being cancelled
# at the job timeout without one.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
all_phases="build packets-bpf load module packets-kfuncs packets-veer wireguard vpn unload"
phases=${*:-$all_phases}
for phase in $phases; do
    case " $all_phases " in
    *" $phase "*) ;;
    *) echo "unknown phase $phase; phases: $all_phases" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" -eq 0 ] || { echo "kernel module integration requires root" >&2; exit 1; }
case " $phases " in
*" load "*) [ ! -d /sys/module/veer_kfuncs ] || { echo "use an isolated test host without an existing veer_kfuncs module" >&2; exit 1; } ;;
esac
# A run that unloads the module owns it: it also unloads it when it fails.
case " $phases " in
*" unload "*) keep_module=0 ;;
*) keep_module=1 ;;
esac
if [ -n "${VEER_KMOD_WORK:-}" ]; then
    work=$VEER_KMOD_WORK
    keep_work=1
    mkdir -p "$work"
else
    work=$(mktemp -d)
    keep_work=0
fi
loaded=0
stuck=0
steps=0
step_pid=
tail_pid=
# shellcheck disable=SC2016 # expanded by the sh -c that runs it
unload='attempts=0
while [ -d /sys/module/veer_kfuncs ] && ! rmmod veer_kfuncs; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 50 ] || exit 1
    sleep 0.2
done'
cleanup() {
    if [ -n "$step_pid" ]; then
        # Pass an interrupt on, as Ctrl-C reached the tests before steps had
        # a session of their own, so they can remove what they set up.
        kill -s INT -- "-$step_pid" 2>/dev/null || true
        waited=0
        while step_running "$step_pid" && [ "$waited" -lt 10 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        signal_step KILL
    fi
    [ -z "$tail_pid" ] || kill "$tail_pid" 2>/dev/null || true
    if [ "$stuck" = 1 ]; then
        echo "leaving veer_kfuncs loaded: a step is stuck in the kernel" >&2
    elif [ "$loaded" = 1 ] && [ "$keep_module" = 0 ]; then
        sh -c "$unload" || true
    fi
    [ "$keep_work" = 1 ] || rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A step is over once its first process has exited; a zombie counts as over.
step_running() {
    state=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1)
    [ -n "$state" ] && [ "$state" != Z ] && [ "$state" != X ]
}

# Signals every process in the step's session, one at a time so that the
# stacks they print do not interleave.
signal_step() {
    for pid in $(ps -s "$step_pid" -o pid= 2>/dev/null); do
        kill -s "$1" "$pid" 2>/dev/null || true
        [ "$1" = KILL ] || sleep 0.2
    done
}

diagnose() {
    echo "--- processes of the step"
    ps -s "$1" -o pid=,stat=,etimes=,wchan:32=,args= 2>/dev/null || true
    for pid in $(ps -s "$1" -o pid= 2>/dev/null); do
        echo "--- kernel stack of $pid"
        cat "/proc/$pid/stack" 2>/dev/null || true
    done
    echo "--- load"
    top -b -n 1 2>/dev/null | head -n 15 || true
    echo "--- network namespaces"
    ip netns list 2>/dev/null || true
    echo "--- veer_kfuncs references: $(cat /sys/module/veer_kfuncs/refcnt 2>/dev/null || echo none)"
    echo "--- kernel log"
    dmesg 2>/dev/null | tail -n 80 || true
}

# step NAME SECONDS SIGNAL COMMAND...
# The command runs in a session of its own, with INT and QUIT at their
# defaults (a background command of a non-interactive shell starts with both
# ignored). SIGNAL is sent to it at the limit and makes it show where it
# waits: QUIT dumps the goroutines of a Go test binary, ABRT the stacks of
# every Python thread (with PYTHONFAULTHANDLER). Python's fault handler prints
# at once and in every process, where a KeyboardInterrupt traceback would wait
# for finally blocks that may be what hangs. KILL follows 30 seconds later.
step() {
    name=$1 limit=$2 signal=$3
    shift 3
    steps=$((steps + 1))
    log="$work/step-$steps.log"
    : > "$log"
    echo "==> $(date -u +%T) $name (limit ${limit}s)"
    started=$(date +%s)
    setsid env --default-signal=INT,QUIT "$@" < /dev/null > "$log" 2>&1 &
    step_pid=$!
    tail -n +1 -f "$log" &
    tail_pid=$!
    waited=0
    timed_out=0
    while step_running "$step_pid"; do
        if [ "$waited" -eq "$limit" ]; then
            timed_out=1
            echo "::error::$name did not finish within ${limit}s"
            diagnose "$step_pid"
            signal_step "$signal"
        elif [ "$waited" -eq $((limit + 30)) ]; then
            signal_step KILL
        elif [ "$waited" -ge $((limit + 40)) ]; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    status=0
    if step_running "$step_pid"; then
        stuck=1
        status=124
        echo "::error::$name cannot be killed; abandoning it"
        diagnose "$step_pid"
    else
        wait "$step_pid" || status=$?
    fi
    # Children may still be writing what they print on their way out.
    sleep 1
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    tail_pid=
    elapsed=$(( $(date +%s) - started ))
    if [ "$timed_out" = 1 ] && [ "$status" = 0 ]; then
        status=124
    fi
    if [ "$status" != 0 ]; then
        echo "::error::$name failed with status $status after ${elapsed}s"
        return "$status"
    fi
    step_pid=
    echo "==> $name passed in ${elapsed}s"
}

need_module() {
    [ -d /sys/module/veer_kfuncs ] || { echo "veer_kfuncs is not loaded; run the load phase first" >&2; exit 1; }
}

cd "$ROOT_DIR"
tests="$ROOT_DIR/internal/app"
for phase in $phases; do
    case $phase in
    build)
        step "build kernel module" 300 TERM sh scripts/build-kernel-module.sh
        step "build eBPF objects" 420 TERM sh scripts/build-all-ebpf.sh
        step "build daemon" 420 TERM env CGO_ENABLED=0 go build -tags veer_kfuncs -o "$work/veer" .
        step "build loader" 300 TERM env CGO_ENABLED=0 go build -o "$work/loader" ./scripts/kfuncs-test-loader
        step "build tests" 420 TERM go test -c -tags veer_kfuncs -o "$work/kfuncs.test" ./internal/app
        ;;
    load)
        step "load module" 60 TERM insmod "kernel/$(uname -r)/veer_kfuncs.ko"
        loaded=1
        ;;
    module)
        need_module
        # The test binary runs in its package directory, as go test runs it.
        step "module tests" 240 QUIT env -C "$tests" VEER_RUN_KFUNCS_TESTS=1 FORWARD_RUN_PLUGIN_INTEGRATION_TEST=1 \
            "$work/kfuncs.test" -test.run '^(TestOptionalKernelModule.*|TestPluginControlNetOwnedLinkMACLinuxIntegration)$' \
            -test.count=1 -test.v -test.timeout=3m
        ;;
    packets-bpf)
        # Plain BPF needs no module; run before the load phase, a failure
        # here does not involve veer_kfuncs. The packet script stops its
        # namespace child after 300 seconds itself.
        step "packets through the loader, plain BPF" 360 ABRT env PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 \
            python3 scripts/verify-kfuncs-packets.py --loader "$work/loader" --mode bpf
        ;;
    packets-kfuncs)
        need_module
        step "packets through the loader, kfuncs" 360 ABRT env PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 \
            python3 scripts/verify-kfuncs-packets.py --loader "$work/loader" --mode kfuncs
        ;;
    packets-veer)
        need_module
        step "packets through veer" 360 ABRT env PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 \
            python3 scripts/verify-kfuncs-packets.py --loader "$work/loader" --direct --veer "$work/veer"
        ;;
    wireguard)
        need_module
        step "WireGuard" 360 QUIT env -C "$tests" VEER_RUN_KFUNCS_TESTS=1 VEER_RUN_WIREGUARD_TESTS=1 FORWARD_PERF_BINARY="$work/veer" \
            "$work/kfuncs.test" -test.run '^TestVPNWireGuardLinuxIntegration$' -test.count=1 -test.v -test.timeout=5m
        ;;
    vpn)
        need_module
        step "VPN cores" 600 QUIT env FORWARD_PERF_BINARY="$work/veer" VEER_VPN_EXPECT_DIRECT=1 sh scripts/verify-vpn-cores.sh
        ;;
    unload)
        step "unload module" 60 TERM sh -c "$unload"
        loaded=0
        ;;
    esac
done
