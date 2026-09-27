from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ApprovalNotification:
    request_id: str
    code: str
    approval_url: str


class Notifier(Protocol):
    def notify(self, *, request_id: str, code: str, approval_url: str) -> None: ...


class LogNotifier:
    """Safe default backend for tests, CI, and headless environments."""

    def __init__(self) -> None:
        self.notifications: list[ApprovalNotification] = []
        self._logger = logging.getLogger("pav.notifications")

    def notify(self, *, request_id: str, code: str, approval_url: str) -> None:
        notification = ApprovalNotification(request_id, code, approval_url)
        self.notifications.append(notification)
        self._logger.info(
            "approval notification request_id=%s code=%s approval_url=%s",
            request_id,
            code,
            approval_url,
        )


class MacOSNotifier:
    """Desktop notification backend; unavailable macOS tooling falls back to logging."""

    def __init__(self, fallback: LogNotifier | None = None) -> None:
        self.fallback = fallback or LogNotifier()

    def notify(self, *, request_id: str, code: str, approval_url: str) -> None:
        if shutil.which("osascript") is None:
            logging.getLogger("pav.notifications").warning(
                "osascript unavailable; using logged approval notification for request_id=%s",
                request_id,
            )
            self.fallback.notify(request_id=request_id, code=code, approval_url=approval_url)
            return
        def apple_string(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"')

        script = (
            f'display notification "Approval code: {apple_string(code)}" & return & '
            f'"Open: {apple_string(approval_url)}" with title "PAV approval required"'
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script], check=False, capture_output=True, text=True
            )
        except OSError:
            result = None
        if result is None or result.returncode != 0:
            logging.getLogger("pav.notifications").warning(
                "osascript failed; using logged approval notification for request_id=%s",
                request_id,
            )
            self.fallback.notify(request_id=request_id, code=code, approval_url=approval_url)


def build_notifier(selection: str | None = None) -> Notifier:
    selected = (selection or os.environ.get("PAV_NOTIFIER", "log")).lower()
    if selected == "macos":
        return MacOSNotifier()
    return LogNotifier()
