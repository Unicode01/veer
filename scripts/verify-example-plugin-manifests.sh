#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
EXAMPLE_DIR=${FORWARD_PLUGIN_EXAMPLE_DIR:-"$ROOT_DIR/examples/plugins"}

find_python() {
	if [ -n "${PYTHON:-}" ]; then
		if "$PYTHON" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$PYTHON"
			return
		fi
		echo "configured PYTHON cannot execute Python code: $PYTHON" >&2
		exit 1
	fi
	for candidate in python3 python python.exe py py.exe; do
		if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	echo "python3 or python is required to verify example plugin manifests" >&2
	exit 1
}

PYTHON_BIN=$(find_python)

"$PYTHON_BIN" - "$EXAMPLE_DIR" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
id_re = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
token_re = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
hash_re = re.compile(r"^[a-f0-9]{64}$")

valid_kind = {"pipeline", "control", "ui"}
valid_stability = {"lab", "preview", "stable", "deprecated"}
hash_required_stability = {"preview", "stable"}
valid_control_permission = {
    "crypto",
    "ebpf.load",
    "ebpf.map_read",
    "ebpf.map_write",
    "hook.attach",
    "kv",
    "net.admin",
    "net.l2",
    "net.udp",
    "plugin.action",
    "plugin.register",
    "plugin.resource",
    "resource",
    "secret",
    "timer",
    "ui",
}
valid_resource_method = {"list", "get", "create", "update", "delete"}
valid_net_operation = {"addr.write", "l2", "link.create", "link.delete", "link.master", "link.offload", "link.read", "link.state", "route.write", "udp"}
reserved_plugin_ids = {"fvtap"}
reserved_resource_ids = {"__kv", "__secret"}
manifest_fields = {"api_version", "id", "name", "version", "description", "kind", "stability", "control"}
runtime_owned_manifest_fields = {"builtin", "capabilities", "virtual_interfaces", "objects", "hooks", "resources", "actions", "ui", "metadata"}
control_fields = {"main", "sha256", "permissions", "resource_access", "action_access", "net_access"}
errors = []
checked = 0


def rel(path, base):
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def add_error(manifest_path, message):
    errors.append(f"{rel(manifest_path, root)}: {message}")


def check_object(manifest_path, value, label):
    if not isinstance(value, dict):
        add_error(manifest_path, f"{label} must be an object")
        return False
    return True


def check_array(manifest_path, value, label):
    if value is None:
        return []
    if not isinstance(value, list):
        add_error(manifest_path, f"{label} must be an array")
        return []
    return value


def check_token(manifest_path, value, label, regex=token_re):
    text = str(value or "").strip().lower()
    if not regex.match(text):
        add_error(manifest_path, f"{label} must match {regex.pattern}")
        return ""
    return text


def check_tokens(manifest_path, values, label, valid=None):
    out = []
    seen = set()
    for index, value in enumerate(check_array(manifest_path, values, label)):
        text = str(value or "").strip().lower()
        if not token_re.match(text):
            add_error(manifest_path, f"{label}[{index}] must match {token_re.pattern}")
            continue
        if valid is not None and text not in valid:
            add_error(manifest_path, f"{label}[{index}] has unsupported value {text!r}")
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def check_unique(manifest_path, seen, key, label):
    if not key:
        return
    if key in seen:
        add_error(manifest_path, f"duplicate {label} {key!r}")
        return
    seen.add(key)


def check_relative_path(manifest_path, value, label):
    text = str(value or "").strip()
    if not text:
        return ""
    if "\x00" in text or "\\" in text:
        add_error(manifest_path, f"{label} contains invalid characters")
        return text
    pure = pathlib.PurePosixPath(text.replace("\\", "/"))
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        add_error(manifest_path, f"{label} must be a relative path inside the plugin directory")
    return text


def safe_child(plugin_dir, manifest_path, label, raw_path):
    value = check_relative_path(manifest_path, raw_path, label)
    if not value:
        return None
    path = (plugin_dir / value).resolve()
    try:
        path.relative_to(plugin_dir.resolve())
    except ValueError:
        add_error(manifest_path, f"{label} escapes plugin directory: {value}")
        return None
    return path


def check_interface_patterns(manifest_path, values, label):
    entries = check_array(manifest_path, values, label)
    if not entries:
        add_error(manifest_path, f"{label} cannot be empty")
        return []
    out = []
    for index, value in enumerate(entries):
        text = str(value or "").strip()
        if not text:
            continue
        if "\x00" in text or any(ch in text for ch in "/\\ \t\r\n") or len(text.encode("utf-8")) > 64:
            add_error(manifest_path, f"{label}[{index}] contains invalid interface pattern {text!r}")
            continue
        if "*" not in text and len(text.encode("utf-8")) > 15:
            add_error(manifest_path, f"{label}[{index}] exceeds Linux interface name length")
            continue
        out.append(text)
    return out


def verify_control(manifest_path, plugin_dir, manifest, stability):
    control = manifest.get("control")
    if not check_object(manifest_path, control, "control"):
        return
    for field in control:
        if field not in control_fields:
            add_error(manifest_path, f"control field {field!r} is unsupported")

    main = str(control.get("main") or "").strip()
    if not main:
        add_error(manifest_path, "control.main is required")
        return
    control_path = safe_child(plugin_dir, manifest_path, "control.main", main)
    if control_path is None:
        return
    if not control_path.is_file():
        add_error(manifest_path, f"control.main is missing: {main}")
        return
    digest = hashlib.sha256(control_path.read_bytes()).hexdigest()

    declared_hash = str(control.get("sha256") or "").strip().lower()
    if declared_hash and not hash_re.match(declared_hash):
        add_error(manifest_path, "control.sha256 must be a lowercase 64-character hex digest")
    elif declared_hash and declared_hash != digest:
        add_error(manifest_path, f"control.sha256 mismatch: expected {declared_hash}, got {digest}")
    elif not declared_hash and stability in hash_required_stability:
        add_error(manifest_path, "control.sha256 is required for stable/preview plugins")

    permissions = check_tokens(manifest_path, control.get("permissions") or [], "control.permissions", valid_control_permission)
    permission_set = set(permissions)

    resource_access = check_array(manifest_path, control.get("resource_access") or [], "control.resource_access")
    if resource_access and "plugin.resource" not in permission_set:
        add_error(manifest_path, "control.resource_access requires plugin.resource permission")
    seen_access = set()
    for index, item in enumerate(resource_access):
        label = f"control.resource_access[{index}]"
        if not check_object(manifest_path, item, label):
            continue
        target_plugin = check_token(manifest_path, item.get("plugin"), f"{label}.plugin", id_re)
        target_resource = check_token(manifest_path, item.get("resource"), f"{label}.resource")
        if target_plugin in reserved_plugin_ids:
            add_error(manifest_path, f"{label}.plugin {target_plugin!r} is reserved")
        if target_resource in reserved_resource_ids:
            add_error(manifest_path, f"{label}.resource {target_resource!r} is reserved")
        check_unique(manifest_path, seen_access, f"{target_plugin}/{target_resource}", "resource access")
        methods = check_tokens(manifest_path, item.get("methods") or [], f"{label}.methods", valid_resource_method)
        if not methods:
            add_error(manifest_path, f"{label}.methods cannot be empty")

    action_access = check_array(manifest_path, control.get("action_access") or [], "control.action_access")
    if action_access and "plugin.action" not in permission_set:
        add_error(manifest_path, "control.action_access requires plugin.action permission")
    seen_action_access = set()
    for index, item in enumerate(action_access):
        label = f"control.action_access[{index}]"
        if not check_object(manifest_path, item, label):
            continue
        target_plugin = check_token(manifest_path, item.get("plugin"), f"{label}.plugin", id_re)
        if target_plugin in reserved_plugin_ids:
            add_error(manifest_path, f"{label}.plugin {target_plugin!r} is reserved")
        actions = check_tokens(manifest_path, item.get("actions") or [], f"{label}.actions")
        if not actions:
            add_error(manifest_path, f"{label}.actions cannot be empty")
        for action in actions:
            check_unique(manifest_path, seen_action_access, f"{target_plugin}/{action}", "action access")

    net_access = check_array(manifest_path, control.get("net_access") or [], "control.net_access")
    if ("net.admin" in permission_set or "net.l2" in permission_set or "net.udp" in permission_set) and not net_access:
        add_error(manifest_path, "control.net_access is required when net.admin, net.l2, or net.udp permission is declared")
    seen_net_access = set()
    for index, item in enumerate(net_access):
        label = f"control.net_access[{index}]"
        if not check_object(manifest_path, item, label):
            continue
        interfaces = check_interface_patterns(manifest_path, item.get("interfaces") or [], f"{label}.interfaces")
        operations = check_tokens(manifest_path, item.get("operations") or [], f"{label}.operations", valid_net_operation)
        if not operations:
            add_error(manifest_path, f"{label}.operations cannot be empty")
        for operation in operations:
            if operation == "l2" and "net.l2" not in permission_set:
                add_error(manifest_path, f"{label}.operation {operation!r} requires net.l2 permission")
            if operation == "udp" and "net.udp" not in permission_set:
                add_error(manifest_path, f"{label}.operation {operation!r} requires net.udp permission")
            if operation not in {"l2", "udp"} and "net.admin" not in permission_set:
                add_error(manifest_path, f"{label}.operation {operation!r} requires net.admin permission")
        key = ",".join(sorted(interfaces)) + ":" + ",".join(operations)
        check_unique(manifest_path, seen_net_access, key, "net access entry")


if not root.is_dir():
    raise SystemExit(f"example plugin directory does not exist: {root}")

for manifest_path in sorted(root.glob("*/plugin.json")):
    checked += 1
    plugin_dir = manifest_path.parent.resolve()
    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        add_error(manifest_path, f"cannot parse JSON: {exc}")
        continue

    if not isinstance(manifest, dict):
        add_error(manifest_path, "manifest must be a JSON object")
        continue

    for field in sorted(manifest):
        if field in runtime_owned_manifest_fields:
            add_error(manifest_path, f"manifest field {field!r} is runtime-owned; register it from control.js")
        elif field not in manifest_fields:
            add_error(manifest_path, f"manifest field {field!r} is unsupported")

    api_version = str(manifest.get("api_version") or "v1").strip().lower()
    if api_version != "v1":
        add_error(manifest_path, f"unsupported api_version {api_version!r}")

    plugin_id = str(manifest.get("id") or "").strip().lower()
    if not plugin_id:
        add_error(manifest_path, "id is required")
    else:
        check_token(manifest_path, plugin_id, "id", id_re)
        if plugin_id != plugin_dir.name:
            add_error(manifest_path, f"id {plugin_id!r} does not match directory {plugin_dir.name!r}")
        if plugin_id in reserved_plugin_ids:
            add_error(manifest_path, f"id {plugin_id!r} is reserved")

    if not str(manifest.get("name") or "").strip():
        add_error(manifest_path, "name is required")
    if not str(manifest.get("version") or "").strip():
        add_error(manifest_path, "version is required")

    kind = str(manifest.get("kind") or "pipeline").strip().lower()
    if kind not in valid_kind:
        add_error(manifest_path, f"kind must be one of {', '.join(sorted(valid_kind))}")

    stability = str(manifest.get("stability") or "lab").strip().lower() or "lab"
    if stability not in valid_stability:
        add_error(manifest_path, f"unknown stability {stability!r}")

    verify_control(manifest_path, plugin_dir, manifest, stability)

if checked == 0:
    errors.append(f"no example plugin manifests found under {root}")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)

print(f"verified {checked} example plugin manifest(s)")
PY
