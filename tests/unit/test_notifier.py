from __future__ import annotations

import subprocess

from pav.adapters.notifications import LogNotifier, MacOSNotifier, build_notifier


def test_log_notifier_captures_code_without_os_delivery() -> None:
    notifier = LogNotifier()

    notifier.notify(request_id="req_test", code="ABCD1234", approval_url="http://127.0.0.1:8000/approvals/req_test")

    assert notifier.notifications[0].code == "ABCD1234"
    assert notifier.notifications[0].approval_url.endswith("/req_test")


def test_macos_osascript_backend_is_only_selected_explicitly(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/osascript")

    default = build_notifier()
    default.notify(request_id="req_default", code="DEFAULT1", approval_url="http://default")
    assert calls == []

    explicit = build_notifier("macos")
    explicit.notify(request_id="req_explicit", code="EXPLICIT1", approval_url="http://explicit")
    assert len(calls) == 1
    assert calls[0][0] == "osascript"
    assert "EXPLICIT1" in calls[0][-1]
    assert "http://explicit" in calls[0][-1]
