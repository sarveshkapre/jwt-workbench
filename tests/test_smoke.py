from __future__ import annotations

import json
import subprocess
import sys


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "--help"], check=False)
    assert proc.returncode == 0


def test_inspect_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "inspect", "--help"], check=False)
    assert proc.returncode == 0


def test_sample_none_outputs_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["alg"] == "none"
    assert isinstance(data["token"], str)


def test_verify_invalid_token_is_clean_error() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            "not-a-jwt",
            "--key-text",
            "secret123",
            "--alg",
            "HS256",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "error:" in proc.stderr.lower()
