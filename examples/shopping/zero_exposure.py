from __future__ import annotations

import asyncio
from dataclasses import dataclass
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import httpx
from mcp import Client

try:
    from examples.demo_support import DEMO_SECRET, call_tool, create_demo_stack, print_json
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from examples.demo_support import DEMO_SECRET, call_tool, create_demo_stack, print_json

from pav.authority.capabilities import MacOSKeychainSecretProvider, SecretProvider
from pav.domain.models import ExternalHandle


DEMO_KEYCHAIN_SECRET = "pav-demo-booking-secret-2026"


@dataclass(frozen=True)
class KeychainEntry:
    service: str
    account: str
    secret: str

    @property
    def uri(self) -> str:
        return f"keychain://{self.service}/{self.account}"


class DemoKeychainUnavailable(RuntimeError):
    pass


def _security(*args: str, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["/usr/bin/security", *args],
            input=input_data,
            stdin=subprocess.DEVNULL if input_data is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as error:
        raise DemoKeychainUnavailable(f"macOS Keychain command unavailable: {type(error).__name__}") from None


def _setup_keychain_entry() -> KeychainEntry:
    entry = KeychainEntry(
        service=f"pav-demo-booking-credential-{uuid4().hex}",
        account="pav-demo",
        secret=DEMO_KEYCHAIN_SECRET,
    )
    result = _security(
        "add-generic-password",
        "-a",
        entry.account,
        "-s",
        entry.service,
        "-T",
        "/usr/bin/security",
        "-w",
        input_data=f"{entry.secret}\n{entry.secret}\n".encode(),
    )
    if result.returncode != 0:
        _cleanup_keychain_entry(entry)
        raise DemoKeychainUnavailable(
            f"macOS Keychain setup failed with exit code {result.returncode}"
        )
    return entry


def _read_keychain_directly(entry: KeychainEntry) -> str:
    result = _security(
        "find-generic-password",
        "-a",
        entry.account,
        "-s",
        entry.service,
        "-w",
    )
    if result.returncode != 0:
        raise DemoKeychainUnavailable("macOS Keychain credential could not be read independently")
    return result.stdout.decode().rstrip("\n")


def _cleanup_keychain_entry(entry: KeychainEntry) -> None:
    deleted = _security(
        "delete-generic-password",
        "-a",
        entry.account,
        "-s",
        entry.service,
    )
    if deleted.returncode not in (0, 44):
        raise RuntimeError("demo Keychain cleanup failed")
    remaining = _security(
        "find-generic-password",
        "-a",
        entry.account,
        "-s",
        entry.service,
        "-w",
    )
    if remaining.returncode == 0:
        raise RuntimeError("demo Keychain item was not removed")


async def _run_workflow(
    *,
    actual_secret: str,
    external_handle: ExternalHandle,
    provider: SecretProvider,
    provider_label: str,
) -> None:
    _, server, app = create_demo_stack(
        external_handle=external_handle,
        secret_provider=provider,
    )
    print(f"credential provider: {provider_label}")
    async with Client(server, raise_exceptions=True) as client:
        request = await call_tool(
            client,
            "vault.request_access",
            {
                "agent_id": "travel-agent",
                "agent_name": "Travel Agent",
                "objective": "Complete the selected hotel booking",
                "purpose": "travel.hotel_booking",
                "items": [
                    {
                        "mode": "use",
                        "resource": "credentials.booking_site",
                        "destination": "booking.example",
                    }
                ],
                "requested_ttl_seconds": 600,
                "max_uses": 1,
            },
        )
        print_json("1. Agent requests USE, never REVEAL, for the booking credential", request)
        assert request["status"] == "approval_required"
        code = next(
            notification.code
            for notification in app.state.notifier.notifications
            if notification.request_id == request["request_id"]
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://pav.local", follow_redirects=True
        ) as browser:
            approved = await browser.post(
                f"/approvals/{request['request_id']}/approve", data={"code": code}
            )
            approved.raise_for_status()
        print("2. User approves the capability at its destination.")

        status = await call_tool(
            client, "vault.get_request_status", {"request_id": request["request_id"]}
        )
        used = await call_tool(
            client,
            "vault.use",
            {
                "grant_id": status["grant"]["id"],
                "capability": "credentials.booking_site",
                "destination": "booking.example",
                "task_id": status["request"]["task_id"],
            },
        )
        sys.stdout.flush()
        print(
            f"actual Keychain value: {actual_secret}",
            file=sys.stderr,
            flush=True,
        )
        print_json("3. vault.use returns an opaque execution handle", used)
        sys.stdout.flush()
        serialized = str(used)
        assert actual_secret not in serialized
        assert DEMO_SECRET not in serialized
        assert "execution_handle" in used
    print("ASSERTION: credential value is absent from the MCP response and never enters caller context.")


async def _run_mock_fallback() -> None:
    authority, _, _ = create_demo_stack()
    await _run_workflow(
        actual_secret="unavailable",
        external_handle=authority.external_handles["credentials.booking_site"],
        provider=authority.secret_providers["mock"],
        provider_label="MockSecretProvider",
    )


async def run(entry: KeychainEntry | None = None) -> None:
    """Run the proof with a real Keychain item, falling back only when unavailable."""
    if entry is not None:
        actual_secret = _read_keychain_directly(entry)
        handle = ExternalHandle(
            name="credentials.booking_site",
            uri=entry.uri,
            provider=MacOSKeychainSecretProvider.provider_name,
            allowed_destinations={"booking.example"},
        )
        await _run_workflow(
            actual_secret=actual_secret,
            external_handle=handle,
            provider=MacOSKeychainSecretProvider(),
            provider_label="MacOSKeychainSecretProvider",
        )
        return

    managed_entry: KeychainEntry | None = None
    try:
        managed_entry = _setup_keychain_entry()
        actual_secret = _read_keychain_directly(managed_entry)
        handle = ExternalHandle(
            name="credentials.booking_site",
            uri=managed_entry.uri,
            provider=MacOSKeychainSecretProvider.provider_name,
            allowed_destinations={"booking.example"},
        )
        try:
            await _run_workflow(
                actual_secret=actual_secret,
                external_handle=handle,
                provider=MacOSKeychainSecretProvider(),
                provider_label="MacOSKeychainSecretProvider",
            )
        except (RuntimeError, OSError) as error:
            print(f"NOTE: macOS Keychain use failed ({error}); falling back to MockSecretProvider.")
            await _run_mock_fallback()
    except DemoKeychainUnavailable as error:
        print(f"NOTE: {error}; falling back to MockSecretProvider.")
        await _run_mock_fallback()
    finally:
        if managed_entry is not None:
            _cleanup_keychain_entry(managed_entry)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
