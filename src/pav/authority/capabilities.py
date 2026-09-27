from __future__ import annotations

from abc import ABC, abstractmethod
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
