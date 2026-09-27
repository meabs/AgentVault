from __future__ import annotations

import asyncio
import subprocess
from uuid import uuid4

import pytest

from examples.shopping.zero_exposure import (
    KeychainEntry,
    main as zero_exposure_main,
    run as zero_exposure_run,
)
from examples.travel.low_risk_context import main as low_risk_main
from examples.travel.progressive_disclosure import main as progressive_main


def _read_keychain_with_test_oracle(entry: KeychainEntry) -> str:
    result = subprocess.run(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            entry.account,
            "-s",
            entry.service,
            "-w",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout.decode().rstrip("\n")


@pytest.fixture
def demo_keychain_entry() -> KeychainEntry:
    entry = KeychainEntry(
        service=f"pav-test-demonstrator-{uuid4().hex}",
        account="pav-test-demonstrator",
        secret="pav-test-demonstrator-secret-2026",
    )
    added = subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-a",
            entry.account,
            "-s",
            entry.service,
            "-T",
            "/usr/bin/security",
            "-w",
        ],
        input=f"{entry.secret}\n{entry.secret}\n".encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    if added.returncode != 0:
        raise RuntimeError(added.stderr.decode(errors="replace"))
    try:
        yield entry
    finally:
        deleted = subprocess.run(
            [
                "/usr/bin/security",
                "delete-generic-password",
                "-a",
                entry.account,
                "-s",
                entry.service,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        assert deleted.returncode in (0, 44), deleted.stderr.decode(errors="replace")
        remaining = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-a",
                entry.account,
                "-s",
                entry.service,
                "-w",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        assert remaining.returncode != 0, "demonstrator Keychain item was not removed"


def test_low_risk_context_demo_completes(capsys) -> None:
    low_risk_main()
    output = capsys.readouterr().out
    assert "without a human approval step" in output


def test_progressive_disclosure_demo_completes(capsys) -> None:
    progressive_main()
    output = capsys.readouterr().out
    assert "approval_required" in output
    assert "date of birth was not requested or returned" in output


def test_zero_exposure_demo_never_prints_mock_secret(capsys) -> None:
    zero_exposure_main()
    output = capsys.readouterr().out
    assert "vault.use returns an opaque execution handle" in output
    assert "demo-booking-secret-NEVER-IN-MCP" not in output
    assert "keychain-exec-" in output or "falling back to MockSecretProvider" in output


def test_zero_exposure_uses_real_keychain_and_keeps_raw_value_out_of_mcp_output(
    demo_keychain_entry: KeychainEntry,
    capsys,
) -> None:
    actual_secret = _read_keychain_with_test_oracle(demo_keychain_entry)

    asyncio.run(zero_exposure_run(demo_keychain_entry))
    captured = capsys.readouterr()

    assert "credential provider: MacOSKeychainSecretProvider" in captured.out
    assert "keychain-exec-" in captured.out
    assert actual_secret not in captured.out
    assert f"actual Keychain value: {actual_secret}" in captured.err
