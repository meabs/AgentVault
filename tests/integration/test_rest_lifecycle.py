from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from pav.adapters.rest.app import create_app
from pav.authority.service import Authority


def _client(authority: Authority) -> TestClient:
    return TestClient(create_app(authority))


def _task(client: TestClient, agent_id: str = "travel-agent") -> str:
    response = client.post(
        "/tasks",
        json={
            "agent": {"id": agent_id, "name": "Travel Agent"},
            "objective": "Book a hotel near Edinburgh Waverley",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _booking_request(client: TestClient, task_id: str, *, ttl: str = "PT10M") -> dict:
    response = client.post(
        f"/tasks/{task_id}/access-requests",
        json={
            "purpose": "travel.hotel_booking",
            "requested_ttl": ttl,
            "items": [
                {"mode": "reveal", "resource": "identity.full_name"},
                {"mode": "reveal", "resource": "identity.email"},
                {"mode": "prove", "resource": "identity.age_over_18"},
                {
                    "mode": "use",
                    "resource": "credentials.booking_site",
                    "destination": "booking.example",
                },
            ],
        },
    )
    assert response.status_code == 201
    return response.json()


def test_rest_full_lifecycle_matches_phase0(authority: Authority) -> None:
    client = _client(authority)
    task_id = _task(client)

    search = client.post(
        f"/tasks/{task_id}/access-requests",
        json={
            "purpose": "travel.hotel_search",
            "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
        },
    )
    assert search.status_code == 201
    search_data = search.json()
    assert search_data["decision"]["outcome"] == "ALLOW"
    search_grant = search_data["grant"]["id"]
    assert client.post(
        f"/grants/{search_grant}/reveal",
        json={"resource": "preferences.travel.airport", "task_id": task_id},
    ).json() == {"attribute": "preferences.travel.airport", "value": "MAN"}

    booking = _booking_request(client, task_id)
    assert booking["decision"]["outcome"] == "APPROVAL_REQUIRED"
    assert booking["grant"] is None
    request_id = booking["request"]["id"]
    assert client.get(f"/access-requests/{request_id}").json()["decision"]["approved"] is False

    approved = client.post(f"/access-requests/{request_id}/approve")
    assert approved.status_code == 201
    grant_id = approved.json()["grant"]["id"]
    assert client.post(
        f"/grants/{grant_id}/reveal",
        json={"resource": "identity.full_name", "task_id": task_id},
    ).json()["value"] == "Garry Smith"
    assert client.post(
        f"/grants/{grant_id}/prove",
        json={"claim": "identity.age_over_18", "task_id": task_id},
    ).json() == {"claim": "identity.age_over_18", "result": True}
    used = client.post(
        f"/grants/{grant_id}/use",
        json={
            "capability": "credentials.booking_site",
            "destination": "booking.example",
            "task_id": task_id,
        },
    )
    assert used.status_code == 200
    assert used.json()["status"] == "authorized"
    assert "booking-secret-DO-NOT-LEAK" not in used.text
    audit = client.get("/audit", params={"task_id": task_id})
    assert audit.status_code == 200
    event_types = {event["event_type"] for event in audit.json()}
    assert {"TASK_CREATED", "APPROVAL_REQUESTED", "APPROVAL_GRANTED", "GRANT_ISSUED", "ATTRIBUTE_REVEALED", "CLAIM_PROVED", "CAPABILITY_USED"} <= event_types


def test_rest_rejects_expired_grant(authority: Authority, clock) -> None:
    client = _client(authority)
    task_id = _task(client)
    response = client.post(
        f"/tasks/{task_id}/access-requests",
        json={
            "purpose": "travel.hotel_search",
            "requested_ttl": "PT1S",
            "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
        },
    )
    grant_id = response.json()["grant"]["id"]
    clock.advance(timedelta(seconds=2))
    expired = client.post(
        f"/grants/{grant_id}/reveal",
        json={"resource": "preferences.travel.airport", "task_id": task_id},
    )
    assert expired.status_code == 410
    assert expired.json()["detail"] == "grant is expired"


def test_rest_rejects_wrong_task(authority: Authority) -> None:
    client = _client(authority)
    task_a = _task(client)
    task_b = _task(client, "research-agent")
    response = client.post(
        f"/tasks/{task_a}/access-requests",
        json={
            "purpose": "travel.hotel_search",
            "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
        },
    )
    grant_id = response.json()["grant"]["id"]
    wrong_task = client.post(
        f"/grants/{grant_id}/reveal",
        json={"resource": "preferences.travel.airport", "task_id": task_b},
    )
    assert wrong_task.status_code == 403


def test_rest_enforces_max_uses(authority: Authority) -> None:
    client = _client(authority)
    task_id = _task(client)
    booking = _booking_request(client, task_id)
    grant_id = client.post(f"/access-requests/{booking['request']['id']}/approve").json()["grant"]["id"]
    payload = {
        "capability": "credentials.booking_site",
        "destination": "booking.example",
        "task_id": task_id,
    }
    assert client.post(f"/grants/{grant_id}/use", json=payload).status_code == 200
    assert client.post(f"/grants/{grant_id}/use", json=payload).status_code == 410


def test_rest_secret_reveal_is_denied(authority: Authority) -> None:
    client = _client(authority)
    task_id = _task(client)
    response = client.post(
        f"/tasks/{task_id}/access-requests",
        json={
            "purpose": "travel.hotel_booking",
            "items": [{"mode": "reveal", "resource": "credentials.booking_site"}],
        },
    )
    assert response.status_code == 201
    assert response.json()["decision"]["outcome"] == "DENY"
    assert response.json()["grant"] is None

