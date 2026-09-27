from __future__ import annotations

from fastapi.testclient import TestClient

from pav.adapters.rest.app import create_app
from pav.authority.service import Authority
from pav.domain.types import AuditEventType, DecisionOutcome, GrantState


def _client(authority: Authority) -> TestClient:
    return TestClient(create_app(authority))


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


def test_approve_button_issues_active_grant_in_domain(authority: Authority) -> None:
    client = _client(authority)
    task_id, request_id = _pending_booking(client)

    response = client.post(f"/approvals/{request_id}/approve", follow_redirects=False)

    assert response.status_code == 303
    decision = authority.decisions[request_id]
    assert decision.approved is True
    grants = [grant for grant in authority.grants.values() if grant.request_id == request_id]
    assert len(grants) == 1
    assert grants[0].task_id == task_id
    assert grants[0].state is GrantState.ACTIVE
    assert "APPROVAL_GRANTED" in {event.event_type.value for event in authority.audit(task=task_id)}


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

    client.post(f"/approvals/{request_id}/approve")
    grant_id = next(grant.id for grant in authority.grants.values() if grant.request_id == request_id)

    grants = client.get("/ui/grants")
    detail = client.get(f"/ui/grants/{grant_id}")
    audit = client.get(f"/ui/tasks/{task_id}/audit")
    assert grants.status_code == detail.status_code == audit.status_code == 200
    assert grant_id in detail.text
    assert "Task story." in audit.text
