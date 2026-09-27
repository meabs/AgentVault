from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

import pytest

from pav.domain.models import ExternalHandle
from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent, Policy
from pav.domain.types import AccessMode, DecisionOutcome


@dataclass(frozen=True)
class KeychainEntry:
    service: str
    account: str
    secret: str

    @property
    def uri(self) -> str:
        return f"keychain://{self.service}/{self.account}"


def _read_keychain_directly(entry: KeychainEntry) -> str:
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
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result.stdout.decode().rstrip("\n")


@pytest.fixture
def keychain_entry() -> KeychainEntry:
    entry = KeychainEntry(
        service=f"pav-test-booking-credential-{uuid4().hex}",
        account="pav-test",
        secret="pav-test-booking-secret-2026",
    )
    add = subprocess.run(
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
    if add.returncode != 0:
        raise RuntimeError(add.stderr.decode(errors="replace"))

    try:
        yield entry
    finally:
        delete = subprocess.run(
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
        if delete.returncode not in (0, 44):
            raise AssertionError(delete.stderr.decode(errors="replace"))
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
        assert remaining.returncode != 0, "test Keychain item was not removed"


def test_keychain_provider_rejects_destination_outside_handle_scope(keychain_entry: KeychainEntry) -> None:
    from pav.authority.capabilities import MacOSKeychainSecretProvider

    provider = MacOSKeychainSecretProvider()
    handle = ExternalHandle(
        name="credentials.booking_site",
        uri=keychain_entry.uri,
        provider="macos-keychain",
        allowed_destinations={"booking.example"},
    )

    assert provider.can_use(handle, "booking.example") is True
    assert provider.can_use(handle, "attacker.example") is False


def test_keychain_provider_executes_without_returning_the_real_secret(
    keychain_entry: KeychainEntry,
) -> None:
    from pav.authority.capabilities import MacOSKeychainSecretProvider

    provider = MacOSKeychainSecretProvider()
    handle = ExternalHandle(
        name="credentials.booking_site",
        uri=keychain_entry.uri,
        provider="macos-keychain",
        allowed_destinations={"booking.example"},
    )

    actual_secret = _read_keychain_directly(keychain_entry)
    result = provider.execute(handle, "use", "booking.example")

    assert result.startswith("keychain-exec-")
    assert actual_secret not in result


def test_authority_uses_keychain_provider_without_secret_in_response_or_audit(
    keychain_entry: KeychainEntry,
) -> None:
    handle = ExternalHandle(
        name="credentials.booking_site",
        uri=keychain_entry.uri,
        provider="macos-keychain",
        allowed_destinations={"booking.example"},
    )
    authority = Authority(
        external_handles={handle.name: handle},
        policies=[
            Policy(
                name="keychain-use-requires-approval",
                mode=AccessMode.USE,
                decision=DecisionOutcome.APPROVAL_REQUIRED,
                max_ttl=timedelta(minutes=10),
                max_uses=1,
            )
        ],
    )
    task = authority.create_task(
        agent=Agent(id="keychain-agent", name="Keychain Agent"),
        objective="Book a hotel",
    )
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_booking",
        items=[
            AccessRequestItem(
                mode=AccessMode.USE,
                resource=handle.name,
                destination="booking.example",
            )
        ],
    )
    decision = authority.evaluate(request)
    grant = authority.authorize(authority.approve(decision))

    actual_secret = _read_keychain_directly(keychain_entry)
    response = authority.use(
        grant=grant,
        capability=handle.name,
        destination="booking.example",
        task=task,
    )

    assert response["status"] == "authorized"
    assert response["execution_handle"].startswith("keychain-exec-")
    assert actual_secret not in repr(response)
    assert actual_secret not in repr(authority.audit(task=task))
