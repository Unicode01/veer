#!/usr/bin/env python3
"""Check BTF packaging against both resolve_btfids output contracts, without root."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


SOURCE = Path(__file__).resolve().parent / "build-kernel-module.sh"
PROBES = Path(__file__).resolve().parent / "build-kfuncs-probes.sh"
MODULE_BUILD = Path(__file__).resolve().parents[1] / "kernel/veer_kfuncs/build.sh"


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def executable(path, body):
    path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    path.chmod(0o755)


def verify(mode):
    with tempfile.TemporaryDirectory(prefix="veer-btf-build-") as tmp:
        root = Path(tmp)
        for name in ("scripts", "kernel/veer_kfuncs", "internal/app/ebpf", "bin", "headers"):
            (root / name).mkdir(parents=True)
        shutil.copy2(SOURCE, root / "scripts/build-kernel-module.sh")
        shutil.copy2(PROBES, root / "scripts/build-kfuncs-probes.sh")
        shutil.copy2(MODULE_BUILD, root / "kernel/veer_kfuncs/build.sh")
        (root / "headers/Makefile").touch()
        (root / "base.btf").write_bytes(b"matching base")
        (root / "initial.btf").write_bytes(b"original type order")
        (root / "final.btf").write_bytes(b"resolved type order")
        (root / "zero.ids").write_bytes(bytes(24))
        (root / "final.ids").write_bytes(bytes(range(24)))
        fixture = root / "fixture.o"
        command("cc", "-x", "c", "-c", "-o", str(fixture), "-", input=b"int fixture;\n")
        command("objcopy", "--add-section", f".BTF_ids={root / 'zero.ids'}", str(fixture))
        if mode == "existing":
            command("objcopy", "--add-section", f".BTF={root / 'final.btf'}",
                    "--update-section", f".BTF_ids={root / 'final.ids'}", str(fixture))
        if mode == "stale-kernel":
            previous = root / "kernel/veer_kfuncs/veer_kfuncs.ko"
            shutil.copy2(fixture, previous)
            command("objcopy", "--add-section", f".BTF={root / 'initial.btf'}", str(previous))

        executable(root / "bin/make", '''
target="$FIXTURE_ROOT/kernel/veer_kfuncs/veer_kfuncs.ko"
for arg do
    if [ "$arg" = clean ]; then rm -f "$target"; exit 0; fi
done
if [ ! -f "$target" ]; then cp "$FIXTURE_ROOT/fixture.o" "$target"; fi
''')
        executable(root / "bin/modinfo", "echo fixture-release SMP\n")
        executable(root / "bin/pahole", '''
for target do :; done
touch "$FIXTURE_ROOT/pahole-called"
objcopy --add-section ".BTF=$FIXTURE_ROOT/initial.btf" "$target"
''')
        executable(root / "bin/clang", '''
for target do :; done
touch "$target"
''')
        if mode in ("legacy", "stale-kernel", "standalone"):
            resolver = '''
objcopy --update-section ".BTF=$FIXTURE_ROOT/final.btf" \\
    --update-section ".BTF_ids=$FIXTURE_ROOT/final.ids" "$3"
'''
        elif mode == "existing":
            resolver = "echo 'must preserve existing resolved BTF' >&2; exit 99\n"
        else:
            resolver = 'cp "$FIXTURE_ROOT/final.btf" "$3.BTF"\n'
            if mode == "sidecars":
                resolver += 'cp "$FIXTURE_ROOT/final.ids" "$3.BTF_ids"\n'
        executable(root / "bin/resolver", resolver)
        env = os.environ.copy()
        env.update({
            "PATH": str(root / "bin") + os.pathsep + env["PATH"],
            "FIXTURE_ROOT": str(root),
            "KDIR": str(root / "headers"),
            "VMLINUX_BTF": str(root / "base.btf"),
            "RESOLVE_BTFIDS": str(root / "bin/resolver"),
            "BPF_CLANG": str(root / "bin/clang"),
        })
        # `veer kfuncs build` runs the module script alone from a private copy.
        script = "kernel/veer_kfuncs/build.sh" if mode == "standalone" else "scripts/build-kernel-module.sh"
        run = subprocess.run(["sh", str(root / script)], env=env, capture_output=True, text=True)
        if mode == "missing-ids":
            assert run.returncode != 0 and "omitted .BTF_ids" in run.stderr, run
            assert not (root / "kernel/fixture-release/veer_kfuncs.ko").exists()
        else:
            assert run.returncode == 0, run.stderr
            module = root / "kernel/fixture-release/veer_kfuncs.ko"
            if mode == "standalone":
                assert not module.exists(), "build.sh must not install into kernel/<release>"
                module = root / "kernel/veer_kfuncs/veer_kfuncs.ko"
            command("objcopy", "--dump-section", f".BTF={root / 'got.btf'}",
                    "--dump-section", f".BTF_ids={root / 'got.ids'}", str(module))
            assert (root / "got.btf").read_bytes() == (root / "final.btf").read_bytes()
            assert (root / "got.ids").read_bytes() == (root / "final.ids").read_bytes()
            assert (root / "pahole-called").exists() == (mode != "existing")
        print("PASS optional module BTF packaging:", mode)


if __name__ == "__main__":
    for case in ("legacy", "sidecars", "existing", "missing-ids", "stale-kernel", "standalone"):
        verify(case)
