from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from pav.adapters.rest.app import create_app
from pav.authority.service import APPROVAL_CODE_MAX_FAILED_ATTEMPTS, Authority
from pav.domain.types import AuditEventType, DecisionOutcome, GrantState


def _client(authority: Authority) -> TestClient:
    return TestClient(create_app(authority))


def _approval_code(client: TestClient, request_id: str) -> str:
    notifications = client.app.state.notifier.notifications
    return next(notification.code for notification in notifications if notification.request_id == request_id)


def _pending_booking(client: TestClient) -> tuple[str, str]:
    task = client.post(
        "/tasks",
        json={
            "agent": {"id": "travel-agent", "name": "Travel Agent", "runtime": "demo-mcp"},
            "objective": "Book a hotel near Edinburgh Waverley",
        },
    )
    assert task.status_code == 201
    task_id = task.json()["id"]
    request = client.post(
        f"/tasks/{task_id}/access-requests",
        json={
            "purpose": "travel.hotel_booking",
            "reason": "Complete the reservation selected by the user.",
            "requested_ttl": "PT10M",
            "items": [
                {"mode": "reveal", "resource": "identity.full_name"},
                {"mode": "prove", "resource": "identity.age_over_18"},
                {
                    "mode": "use",
                    "resource": "credentials.booking_site",
                    "destination": "booking.example",
                },
            ],
        },
    )
    assert request.status_code == 201
    payload = request.json()
    assert payload["decision"]["outcome"] == "APPROVAL_REQUIRED"
    return task_id, payload["request"]["id"]


def test_approval_screen_explains_each_mode_and_five_questions(authority: Authority) -> None:
    client = _client(authority)
    _, request_id = _pending_booking(client)

    response = client.get(f"/approvals/{request_id}")

    assert response.status_code == 200
    assert "Who is asking?" in response.text
    assert "What do they want?" in response.text
    assert "Why do they want it?" in response.text
    assert "Where will it be used?" in response.text
    assert "For how long?" in response.text
    assert "REVEAL" in response.text
    assert "PROVE" in response.text
    assert "USE" in response.text
    assert "Date of birth will not be shared." in response.text
    assert "credential value will not be shared" in response.text
    assert "Identity · Full Name" in response.text
    assert "booking.example" in response.text
    assert "Approve request" in response.text
    assert "Deny request" in response.text
    assert "A human-presence code was sent" in response.text
    assert 'name="code"' in response.text
    assert _approval_code(client, request_id) not in response.text


def test_approve_button_issues_active_grant_in_domain(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)

    code = _approval_code(client, request_id)
    response = client.post(
        f"/approvals/{request_id}/approve",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 303
    decision = authority.decisions[request_id]
    assert decision.approved is True
    grants = [grant for grant in authority.grants.values() if grant.request_id == request_id]
    assert len(grants) == 1
    assert grants[0].task_id == task_id
    assert grants[0].state is GrantState.ACTIVE
    assert "APPROVAL_GRANTED" in {event.event_type.value for event in authority.audit(task=task_id)}


def test_approval_without_code_cannot_issue_grant_and_is_audited(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)

    response = client.post(f"/approvals/{request_id}/approve", follow_redirects=False)

    assert response.status_code == 403
    assert "approval code is required" in response.json()["detail"]
    assert not [grant for grant in authority.grants.values() if grant.request_id == request_id]
    rejected = [event for event in authority.audit(task=task_id) if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED]
    assert rejected[-1].metadata["reason"] == "missing"


def test_legacy_direct_rest_approval_route_is_not_available(authority: Authority) -> None:
    client = _client(authority)
    _, request_id = _pending_booking(client)

    response = client.post(f"/access-requests/{request_id}/approve")

    assert response.status_code == 404
    assert not [grant for grant in authority.grants.values() if grant.request_id == request_id]


def test_wrong_approval_code_fails_and_is_audited(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)

    response = client.post(
        f"/approvals/{request_id}/approve",
        data={"code": "WRONG-CODE"},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert "incorrect" in response.json()["detail"]
    assert not [grant for grant in authority.grants.values() if grant.request_id == request_id]
    rejected = [event for event in authority.audit(task=task_id) if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED]
    assert rejected[-1].metadata["reason"] == "incorrect"


def test_repeated_wrong_codes_lock_out_the_current_code(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)
    correct_code = _approval_code(client, request_id)

    for attempt in range(APPROVAL_CODE_MAX_FAILED_ATTEMPTS):
        response = client.post(
            f"/approvals/{request_id}/approve",
            data={"code": f"WRONG-CODE-{attempt}"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    still_locked = client.post(
        f"/approvals/{request_id}/approve",
        data={"code": correct_code},
        follow_redirects=False,
    )

    assert still_locked.status_code == 403
    assert "locked out" in still_locked.json()["detail"]
    status = client.get(f"/access-requests/{request_id}").json()
    assert status["decision"]["outcome"] == "APPROVAL_REQUIRED"
    assert status["grant"] is None
    events = [
        event
        for event in authority.audit(task=task_id)
        if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED
    ]
    assert events[-1].metadata["reason"] == "locked_out"
    assert any(event.metadata["reason"] == "incorrect" for event in events)


def test_resending_after_lockout_issues_a_fresh_working_code(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)
    original_code = _approval_code(client, request_id)

    for attempt in range(APPROVAL_CODE_MAX_FAILED_ATTEMPTS):
        client.post(
            f"/approvals/{request_id}/approve",
            data={"code": f"WRONG-CODE-{attempt}"},
            follow_redirects=False,
        )

    resent = client.post(f"/approvals/{request_id}/resend", follow_redirects=False)
    fresh_code = client.app.state.notifier.notifications[-1].code

    assert resent.status_code == 303
    assert fresh_code != original_code
    approved = client.post(
        f"/approvals/{request_id}/approve",
        data={"code": fresh_code},
        follow_redirects=False,
    )

    assert approved.status_code == 303
    assert len([grant for grant in authority.grants.values() if grant.request_id == request_id]) == 1
    assert authority.approval_challenges[request_id].failed_attempts == 0
    assert authority.audit(task=task_id)


def test_expired_approval_code_fails_even_when_originally_correct(authority: Authority, clock) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)
    code = _approval_code(client, request_id)
    clock.advance(timedelta(minutes=6))

    response = client.post(
        f"/approvals/{request_id}/approve",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert "expired" in response.json()["detail"]
    assert not [grant for grant in authority.grants.values() if grant.request_id == request_id]
    rejected = [event for event in authority.audit(task=task_id) if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED]
    assert rejected[-1].metadata["reason"] == "expired"


def test_approval_code_cannot_be_reused_after_successful_approval(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)
    code = _approval_code(client, request_id)

    first = client.post(f"/approvals/{request_id}/approve", data={"code": code}, follow_redirects=False)
    second = client.post(f"/approvals/{request_id}/approve", data={"code": code}, follow_redirects=False)

    assert first.status_code == 303
    assert second.status_code == 403
    assert "already used" in second.json()["detail"]
    assert len([grant for grant in authority.grants.values() if grant.request_id == request_id]) == 1
    rejected = [event for event in authority.audit(task=task_id) if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED]
    assert rejected[-1].metadata["reason"] == "already_used"


def test_deny_button_records_denial_and_issues_no_grant(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)

    response = client.post(f"/approvals/{request_id}/deny", follow_redirects=False)

    assert response.status_code == 303
    decision = authority.decisions[request_id]
    assert decision.outcome is DecisionOutcome.DENY
    assert decision.approved is False
    assert not [grant for grant in authority.grants.values() if grant.request_id == request_id]
    assert AuditEventType.APPROVAL_DENIED in {
        event.event_type for event in authority.audit(task=task_id)
    }
    denied_screen = client.get(f"/approvals/{request_id}")
    assert "No grant was issued" in denied_screen.text


def test_home_grants_and_audit_pages_render_readable_views(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)
    assert client.get("/").status_code == 200
    assert "Pending requests" in client.get("/").text

    client.post(
        f"/approvals/{request_id}/approve",
        data={"code": _approval_code(client, request_id)},
    )
    grant_id = next(grant.id for grant in authority.grants.values() if grant.request_id == request_id)

    grants = client.get("/ui/grants")
    detail = client.get(f"/ui/grants/{grant_id}")
    audit = client.get(f"/ui/tasks/{task_id}/audit")
    assert grants.status_code == detail.status_code == audit.status_code == 200
    assert grant_id in detail.text
    assert "Task story." in audit.text


def test_task_audit_page_surfaces_chain_verification(authority: Authority) -> None:
    client = _client(authority)
    task_id, _ = _pending_booking(client)

    verified = client.get(f"/ui/tasks/{task_id}/audit")

    assert verified.status_code == 200
    assert "Audit chain verified" in verified.text

    authority.storage.audit_events[1].metadata["tampered"] = True

    broken = client.get(f"/ui/tasks/{task_id}/audit")

    assert broken.status_code == 200
    assert "Audit chain broken" in broken.text
    assert "sequence 2" in broken.text
