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


def main() -> None:
    script = load_embedded_config_script()
    compile(script, "deploy.sh:sync_config_file", "exec")

    with tempfile.TemporaryDirectory(prefix="veer-deploy-config-policy-") as temp_dir:
        root = Path(temp_dir)
        legacy = {
            "web_bind": "0.0.0.0",
            "web_token": "short-token",
            "plugin_admin_token": "short-admin",
        }
        result = run_scenario(script, root, "legacy-remote-short", legacy)
        assert result is not None
        assert result["web_token"] == "short-token"
        assert result["plugin_admin_token"] == "short-admin"

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

    print("deploy config compatibility policy: ok")


if __name__ == "__main__":
    main()
