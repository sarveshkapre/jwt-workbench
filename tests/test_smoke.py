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


def test_decode_reads_token_from_stdin() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "none"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    token = json.loads(sample.stdout)["token"]
    proc = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "decode", "--token", "-"],
        check=False,
        input=token,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    decoded = json.loads(proc.stdout)
    assert decoded["header"]["alg"] == "none"


def test_verify_reads_key_from_stdin() -> None:
    sample = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "sample", "--kind", "rs256-pem"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert sample.returncode == 0
    data = json.loads(sample.stdout)
    token = data["token"]
    key_text = data["verify_key"]["key_text"]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "verify",
            "--token",
            token,
            "--alg",
            "RS256",
            "--key-text",
            "-",
        ],
        check=False,
        input=key_text,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_sign_accepts_headers() -> None:
    signed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jwt_workbench",
            "sign",
            "--alg",
            "none",
            "--payload",
            '{"sub":"x"}',
            "--headers",
            '{"foo":"bar"}',
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert signed.returncode == 0
    token = signed.stdout.strip()

    decoded = subprocess.run(
        [sys.executable, "-m", "jwt_workbench", "decode", "--token", token],
        check=False,
        capture_output=True,
        text=True,
    )
    assert decoded.returncode == 0
    header = json.loads(decoded.stdout)["header"]
    assert header["foo"] == "bar"
