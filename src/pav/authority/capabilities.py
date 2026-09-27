from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import subprocess
from urllib.parse import unquote, urlparse
from uuid import uuid4

from pav.domain.models import ExternalHandle


class SecretProvider(ABC):
    @abstractmethod
    def can_use(self, handle: ExternalHandle, destination: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def execute(self, handle: ExternalHandle, operation: str, destination: str) -> str:
        raise NotImplementedError


class MockSecretProvider(SecretProvider):
    """Test adapter that keeps the secret private and returns opaque handles."""

    def __init__(self, secrets: dict[str, str], allowed_destinations: dict[str, set[str]] | None = None) -> None:
        self._secrets = dict(secrets)
        self._allowed_destinations = allowed_destinations or {}

    def can_use(self, handle: ExternalHandle, destination: str) -> bool:
        allowed = self._allowed_destinations.get(handle.name)
        return allowed is None or destination in allowed

    def execute(self, handle: ExternalHandle, operation: str, destination: str) -> str:
        if handle.name not in self._secrets:
            raise KeyError(f"no mock secret configured for {handle.name}")
        if not self.can_use(handle, destination):
            raise PermissionError(f"destination is not allowed for {handle.name}")
        return f"exec_{uuid4().hex}"


class MacOSKeychainSecretProvider(SecretProvider):
    """Use a macOS Keychain generic-password item without exposing its value."""

    provider_name = "macos-keychain"
    keychain_scheme = "keychain"
    security_path = "/usr/bin/security"
    read_timeout_seconds = 5

    def can_use(self, handle: ExternalHandle, destination: str) -> bool:
        return (
            handle.provider == self.provider_name
            and self._coordinates(handle) is not None
            and destination in handle.allowed_destinations
        )

    def execute(self, handle: ExternalHandle, operation: str, destination: str) -> str:
        if operation != "use":
            raise ValueError("macOS Keychain provider only supports use operations")
        if not self.can_use(handle, destination):
            raise PermissionError(f"destination is not allowed for {handle.name}")

        service, account = self._coordinates(handle)  # validated by can_use above
        try:
            result = subprocess.run(
                [
                    self.security_path,
                    "find-generic-password",
                    "-a",
                    account,
                    "-s",
                    service,
                    "-w",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.read_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("macOS Keychain read timed out") from None
        if result.returncode != 0:
            raise RuntimeError("macOS Keychain credential could not be read")

        secret = result.stdout.rstrip(b"\n")
        if not secret:
            raise RuntimeError("macOS Keychain returned an empty credential")

        fingerprint = hashlib.sha256(secret).hexdigest()[:16]
        return f"keychain-exec-{fingerprint}"

    def _coordinates(self, handle: ExternalHandle) -> tuple[str, str] | None:
        parsed = urlparse(handle.uri)
        if parsed.scheme != self.keychain_scheme or not parsed.netloc:
            return None
        account = unquote(parsed.path.lstrip("/"))
        if not account or parsed.query or parsed.fragment:
            return None
        return unquote(parsed.netloc), account
