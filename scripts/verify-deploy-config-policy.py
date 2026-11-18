#!/usr/bin/env python3

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Optional


ROOT_DIR = Path(__file__).resolve().parent.parent
DEPLOY_SCRIPT = ROOT_DIR / "deploy.sh"
EXAMPLE_CONFIG = ROOT_DIR / "config.example.json"
EMBEDDED_CONFIG_PATTERN = re.compile(
    r'''python3 - "\$config_path" <<'PY'\r?\n(?P<body>.*?)\r?\nPY''',
    re.DOTALL,
)
STRONG_WEB_TOKEN = "0123456789abcdefghijklmnopqrstuv"
STRONG_ADMIN_TOKEN = "zyxwvutsrqponmlkjihgfedcba987654"


def load_embedded_config_script() -> str:
    match = EMBEDDED_CONFIG_PATTERN.search(DEPLOY_SCRIPT.read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError("deploy.sh sync_config_file Python block was not found")
    return match.group("body")


def run_scenario(
    script: str,
    root: Path,
    name: str,
    current: Optional[dict],
    *,
    web_bind: str = "127.0.0.1",
    web_bind_explicit: bool = False,
    web_token: str = "unused-default",
    web_token_explicit: bool = False,
    plugin_admin_token: str = STRONG_ADMIN_TOKEN,
    plugin_admin_token_explicit: bool = False,
    web_tls: Optional[bool] = None,
    expected_exit: int = 0,
    expected_error_field: str = "",
) -> Optional[dict]:
    config_path = root / f"{name}.json"
    if current is not None:
        config_path.write_text(json.dumps(current), encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "FORWARD_DEPLOY_CONFIG_TEMPLATE_PATH": "",
            "FORWARD_DEPLOY_DEFAULT_WEB_BIND": "127.0.0.1",
            "FORWARD_DEPLOY_DEFAULT_WEB_UI_ENABLED": "true",
            "FORWARD_DEPLOY_DEFAULT_WEB_PORT": "8080",
            "FORWARD_DEPLOY_DEFAULT_WEB_TOKEN": STRONG_WEB_TOKEN,
            "FORWARD_DEPLOY_DEFAULT_PLUGIN_ADMIN_TOKEN": STRONG_ADMIN_TOKEN,
            "FORWARD_DEPLOY_EXPLICIT_WEB_BIND": "1" if web_bind_explicit else "0",
            "FORWARD_DEPLOY_EXPLICIT_WEB_UI_ENABLED": "0",
            "FORWARD_DEPLOY_EXPLICIT_WEB_PORT": "0",
            "FORWARD_DEPLOY_EXPLICIT_WEB_TOKEN": "1" if web_token_explicit else "0",
            "FORWARD_DEPLOY_EXPLICIT_PLUGIN_ADMIN_TOKEN": "1" if plugin_admin_token_explicit else "0",
            "FORWARD_DEPLOY_WEB_BIND": web_bind,
            "FORWARD_DEPLOY_WEB_UI_ENABLED": "true",
            "FORWARD_DEPLOY_WEB_PORT": "8080",
            "FORWARD_DEPLOY_WEB_TOKEN": web_token,
            "FORWARD_DEPLOY_PLUGIN_ADMIN_TOKEN": plugin_admin_token,
            "FORWARD_DEPLOY_EXPLICIT_WEB_TLS": "0" if web_tls is None else "1",
            "FORWARD_DEPLOY_WEB_TLS": "false" if web_tls is False else "true",
            "PYTHONUTF8": "1",
        }
    )
    completed = subprocess.run(
        [sys.executable, "-", str(config_path)],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        env=env,
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != expected_exit:
        raise AssertionError(
            f"{name}: exit={completed.returncode}, want={expected_exit}, output={output!r}"
        )
    if expected_error_field and expected_error_field not in output:
        raise AssertionError(f"{name}: missing {expected_error_field!r} in {output!r}")
    if completed.returncode != 0:
        return None
    return json.loads(config_path.read_text(encoding="utf-8"))


def result_new_tls(script: str, root: Path) -> Optional[bool]:
    result = run_scenario(script, root, "new-tls-default", None)
    return None if result is None else result.get("web_tls")


def main() -> None:
    script = load_embedded_config_script()
    compile(script, "deploy.sh:sync_config_file", "exec")

    with tempfile.TemporaryDirectory(prefix="veer-deploy-config-policy-") as temp_dir:
        root = Path(temp_dir)
        result = run_scenario(script, root, "new-local-full-defaults", None)
        expected = json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
        expected["web_token"] = STRONG_WEB_TOKEN
        expected["plugin_admin_token"] = STRONG_ADMIN_TOKEN
        assert result == expected, "deploy.sh hardcoded defaults differ from config.example.json"

        legacy = {
            "web_bind": "0.0.0.0",
            "web_token": "short-token",
            "plugin_admin_token": "short-admin",
        }
        result = run_scenario(script, root, "legacy-remote-short", legacy)
        assert result is not None
        assert result["web_token"] == "short-token"
        assert result["plugin_admin_token"] == "short-admin"
        # A config from before web_tls keeps plain HTTP; a new one gets HTTPS.
        assert result["web_tls"] is False, result.get("web_tls")
        assert result_new_tls(script, root) is True

        local = {"web_bind": "127.0.0.1", "web_token": STRONG_WEB_TOKEN, "plugin_admin_token": STRONG_ADMIN_TOKEN}
        result = run_scenario(script, root, "existing-keeps-tls-on", dict(local, web_tls=True))
        assert result is not None and result["web_tls"] is True
        result = run_scenario(script, root, "existing-opts-into-tls", local, web_tls=True)
        assert result is not None and result["web_tls"] is True
        result = run_scenario(script, root, "existing-turns-tls-off", dict(local, web_tls=True), web_tls=False)
        assert result is not None and result["web_tls"] is False
        result = run_scenario(script, root, "new-without-tls", None, web_tls=False)
        assert result is not None and result["web_tls"] is False
        run_scenario(
            script,
            root,
            "existing-tls-not-bool",
            dict(local, web_tls="yes"),
            expected_exit=1,
            expected_error_field="web_tls",
        )

        result = run_scenario(
            script,
            root,
            "legacy-explicit-same",
            legacy,
            web_bind="0.0.0.0",
            web_bind_explicit=True,
            web_token="short-token",
            web_token_explicit=True,
        )
        assert result is not None and result["web_token"] == "short-token"

        run_scenario(
            script,
            root,
            "first-remote-exposure",
            {"web_bind": "127.0.0.1", "web_token": "short-token", "plugin_admin_token": ""},
            web_bind="0.0.0.0",
            web_bind_explicit=True,
            expected_exit=1,
            expected_error_field="web_token",
        )
        run_scenario(
            script,
            root,
            "changed-short-token",
            {"web_bind": "0.0.0.0", "web_token": "old-short", "plugin_admin_token": ""},
            web_token="new-short",
            web_token_explicit=True,
            expected_exit=1,
            expected_error_field="web_token",
        )
        run_scenario(
            script,
            root,
            "changed-short-admin-token",
            {
                "web_bind": "0.0.0.0",
                "web_token": STRONG_WEB_TOKEN,
                "plugin_admin_token": STRONG_ADMIN_TOKEN,
            },
            plugin_admin_token="new-short-admin",
            plugin_admin_token_explicit=True,
            expected_exit=1,
            expected_error_field="plugin_admin_token",
        )
        run_scenario(
            script,
            root,
            "new-remote-short",
            None,
            web_bind="0.0.0.0",
            web_bind_explicit=True,
            web_token="new-short",
            web_token_explicit=True,
            expected_exit=1,
            expected_error_field="web_token",
        )
        result = run_scenario(
            script,
            root,
            "new-remote-generated-token",
            None,
            web_bind="0.0.0.0",
            web_bind_explicit=True,
        )
        assert result is not None and result["web_token"] == STRONG_WEB_TOKEN

        # kernel_tc_flow_cache left experimental_features: an older config
        # keeps its choice, and a top-level value already present wins. One
        # that never chose gets the default, on.
        for name, current, want in (
            ("flow-cache-default", {"experimental_features": {"kernel_tc_diag": True}}, True),
            ("flow-cache-legacy-on", {"experimental_features": {"kernel_tc_flow_cache": True, "kernel_tc_diag": True}}, True),
            ("flow-cache-legacy-off", {"experimental_features": {"kernel_tc_flow_cache": False}}, False),
            ("flow-cache-setting-wins", {"kernel_tc_flow_cache": False, "experimental_features": {"kernel_tc_flow_cache": True}}, False),
            ("flow-cache-setting-kept", {"kernel_tc_flow_cache": True, "experimental_features": {}}, True),
        ):
            current.update({"web_token": STRONG_WEB_TOKEN, "plugin_admin_token": STRONG_ADMIN_TOKEN})
            result = run_scenario(script, root, name, current)
            assert result is not None
            assert result["kernel_tc_flow_cache"] is want, f"{name}: kernel_tc_flow_cache = {result['kernel_tc_flow_cache']!r}"
            others = {k: v for k, v in current["experimental_features"].items() if k != "kernel_tc_flow_cache"}
            assert result["experimental_features"] == others, f"{name}: {result['experimental_features']!r}"

        # xdp_generic left experimental_features and is on by default. The old
        # entry was written as false into every config, so it is dropped
        # without being carried over; a top-level value already present wins.
        for name, current, want in (
            ("xdp-generic-default", {"experimental_features": {"kernel_tc_diag": True}}, True),
            ("xdp-generic-legacy-off", {"experimental_features": {"xdp_generic": False, "kernel_tc_diag": True}}, True),
            ("xdp-generic-legacy-on", {"experimental_features": {"xdp_generic": True}}, True),
            ("xdp-generic-setting-kept", {"xdp_generic": False, "experimental_features": {"xdp_generic": True}}, False),
        ):
            current.update({"web_token": STRONG_WEB_TOKEN, "plugin_admin_token": STRONG_ADMIN_TOKEN})
            result = run_scenario(script, root, name, current)
            assert result is not None
            assert result["xdp_generic"] is want, f"{name}: xdp_generic = {result['xdp_generic']!r}"
            others = {k: v for k, v in current["experimental_features"].items() if k != "xdp_generic"}
            assert result["experimental_features"] == others, f"{name}: {result['experimental_features']!r}"

    print("deploy config compatibility policy: ok")


if __name__ == "__main__":
    main()
