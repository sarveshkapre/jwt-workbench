from __future__ import annotations

import subprocess
import sys


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "--help"], check=False)
    assert proc.returncode == 0


def test_inspect_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "jwt_workbench", "inspect", "--help"], check=False)
    assert proc.returncode == 0
