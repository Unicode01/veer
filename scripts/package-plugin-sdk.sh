#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${VEER_PLUGIN_SDK_OUTPUT:-"$ROOT_DIR/veer-plugin-sdk.tar.gz"}

find_python() {
	if [ -n "${PYTHON:-}" ]; then
		"$PYTHON" -c 'import sys' >/dev/null 2>&1 || {
			echo "configured PYTHON cannot execute Python code: $PYTHON" >&2
			exit 1
		}
		printf '%s\n' "$PYTHON"
		return
	fi
	for candidate in python3 python python.exe py py.exe; do
		if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
			printf '%s\n' "$candidate"
			return
		fi
	done
	echo "python3 or python is required to package the plugin SDK" >&2
	exit 1
}

PYTHON_BIN=$(find_python)

"$PYTHON_BIN" - "$ROOT_DIR" "$OUTPUT" <<'PY'
import gzip
import hashlib
import io
import json
import os
import pathlib
import tarfile
import tempfile
import sys

root = pathlib.Path(sys.argv[1]).resolve()
raw_output = pathlib.Path(sys.argv[2])
if not raw_output.is_absolute():
    raw_output = pathlib.Path.cwd() / raw_output
if raw_output.is_symlink():
    raise SystemExit(f"plugin SDK output cannot be a symlink: {raw_output}")
output = raw_output.parent.resolve() / raw_output.name
if output.is_symlink():
    raise SystemExit(f"plugin SDK output cannot be a symlink: {output}")
output.parent.mkdir(parents=True, exist_ok=True)

sources = [
    ("PLUGIN.md", root / "PLUGIN.md"),
    ("LICENSE", root / "LICENSE"),
    ("sdk/plugin", root / "sdk" / "plugin"),
    ("plugins/include", root / "plugins" / "include"),
]

files = []
for archive_root, source in sources:
    source.lstat()
    if source.is_symlink():
        raise SystemExit(f"plugin SDK source cannot be a symlink: {source}")
    if source.is_file():
        files.append((archive_root, source))
        continue
    if not source.is_dir():
        raise SystemExit(f"plugin SDK source must be a regular file or directory: {source}")
    for child in sorted(source.rglob("*")):
        child.lstat()
        if child.is_symlink():
            raise SystemExit(f"plugin SDK source cannot contain symlinks: {child}")
        if child.is_dir():
            continue
        if not child.is_file():
            raise SystemExit(f"plugin SDK source must contain regular files only: {child}")
        relative = child.relative_to(source).as_posix()
        files.append((f"{archive_root}/{relative}", child))

if not files:
    raise SystemExit("plugin SDK has no files")
if len(files) > 512:
    raise SystemExit("plugin SDK contains too many files")

contract_path = root / "sdk" / "plugin" / "api-contract.json"
with contract_path.open("r", encoding="utf-8") as stream:
    contract = json.load(stream)
runtime = contract.get("runtime") if isinstance(contract.get("runtime"), dict) else {}

entries = []
payloads = {}
total_bytes = 0
for archive_path, source in sorted(files):
    data = source.read_bytes()
    if len(data) > 8 * 1024 * 1024:
        raise SystemExit(f"plugin SDK file is too large: {source}")
    total_bytes += len(data)
    if total_bytes > 32 * 1024 * 1024:
        raise SystemExit("plugin SDK expands beyond 32 MiB")
    path = f"veer-plugin-sdk/{archive_path}"
    payloads[path] = data
    entries.append({
        "path": archive_path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })

manifest = {
    "format_version": 1,
    "runtime_version": str(runtime.get("runtime_version") or ""),
    "control_api_abi": int(runtime.get("control_api_abi") or 0),
    "tc_pipeline_abi": int(runtime.get("tc_pipeline_abi") or 0),
    "sdk_contract_version": int(contract.get("version") or 0),
    "files": entries,
}
manifest_data = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
payloads["veer-plugin-sdk/sdk-manifest.json"] = manifest_data

directories = {"veer-plugin-sdk"}
for name in payloads:
    current = pathlib.PurePosixPath(name).parent
    while str(current) not in ("", "."):
        directories.add(current.as_posix())
        current = current.parent

fd, temp_name = tempfile.mkstemp(prefix=".veer-plugin-sdk-", suffix=".tar.gz", dir=output.parent)
os.close(fd)
temp = pathlib.Path(temp_name)
try:
    with temp.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name in sorted(directories):
                    item = tarfile.TarInfo(name + "/")
                    item.type = tarfile.DIRTYPE
                    item.mode = 0o755
                    item.uid = item.gid = 0
                    item.uname = item.gname = ""
                    item.mtime = 0
                    archive.addfile(item)
                for name in sorted(payloads):
                    data = payloads[name]
                    item = tarfile.TarInfo(name)
                    item.mode = 0o755 if name.endswith(".sh") else 0o644
                    item.size = len(data)
                    item.uid = item.gid = 0
                    item.uname = item.gname = ""
                    item.mtime = 0
                    archive.addfile(item, io.BytesIO(data))

    with tarfile.open(temp, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name.rstrip("/") for member in members]
        if len(names) != len(set(names)):
            raise SystemExit("plugin SDK archive contains duplicate entries")
        for member in members:
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise SystemExit(f"plugin SDK archive contains an unsupported entry: {member.name}")
        for name, expected in payloads.items():
            member = archive.getmember(name)
            stream = archive.extractfile(member)
            if stream is None or stream.read() != expected:
                raise SystemExit(f"plugin SDK archive verification failed: {name}")

    os.chmod(temp, 0o644)
    os.replace(temp, output)
finally:
    try:
        temp.unlink()
    except FileNotFoundError:
        pass

print(f"packaged plugin SDK into {output}")
PY
