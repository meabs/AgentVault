from __future__ import annotations

import asyncio
from datetime import timedelta

from mcp import Client

from pav.adapters.mcp.server import create_server
from pav.authority.service import Authority


def _call(server, name: str, arguments: dict) -> dict:
    async def run() -> dict:
        async with Client(server, raise_exceptions=True) as client:
            result = await client.call_tool(name, arguments)
            assert not result.is_error, result.content
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def _failed_call(server, name: str, arguments: dict) -> str:
    async def run() -> str:
        async with Client(server, raise_exceptions=False) as client:
            result = await client.call_tool(name, arguments)
            assert result.is_error
            return result.content[0].text

    return asyncio.run(run())


def _list_tools(server) -> set[str]:
    async def run() -> set[str]:
        async with Client(server) as client:
            result = await client.list_tools()
            return {tool.name for tool in result.tools}

    return asyncio.run(run())


def _request_args(**overrides: object) -> dict:
    args = {
        "agent_id": "travel-agent",
        "agent_name": "Travel Agent",
        "objective": "Book a hotel near Edinburgh Waverley",
        "purpose": "travel.hotel_booking",
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
    }
    args.update(overrides)
    return args


def test_mcp_lists_tools_and_stops_before_human_approval(authority: Authority) -> None:
    server = create_server(authority)
    assert _list_tools(server) == {
        "vault.list_available_context",
        "vault.request_access",
        "vault.get_request_status",
        "vault.reveal",
        "vault.prove",
        "vault.use",
        "vault.get_grant",
        "vault.revoke_grant",
    }

    search = _call(
        server,
        "vault.request_access",
        {
            "agent_id": "travel-agent",
            "agent_name": "Travel Agent",
            "objective": "Find a hotel near Edinburgh Waverley",
            "purpose": "travel.hotel_search",
            "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
        },
    )
    assert search["status"] == "granted"
    task_id = search["task"]["id"]
    search_grant_id = search["grant"]["id"]
    assert _call(
        server,
        "vault.reveal",
        {
            "grant_id": search_grant_id,
            "resource": "preferences.travel.airport",
            "task_id": task_id,
        },
    ) == {"attribute": "preferences.travel.airport", "value": "MAN"}

    booking = _call(
        server,
        "vault.request_access",
        _request_args(task_id=task_id, requested_ttl_seconds=600),
    )
    assert booking["status"] == "approval_required"
    assert booking["grant"] is None
    request_id = booking["request"]["id"]
    assert booking["approval_url"].endswith(f"/approvals/{request_id}")
    assert _call(server, "vault.get_request_status", {"request_id": request_id})["decision"]["approved"] is False

    revoked = _call(server, "vault.revoke_grant", {"grant_id": search_grant_id})
    assert revoked["state"] == "revoked"
    assert _call(server, "vault.get_grant", {"grant_id": search_grant_id})["state"] == "revoked"


def test_mcp_discovery_contains_metadata_but_no_values(authority: Authority, secret_value: str) -> None:
    server = create_server(authority)
    discovery = _call(server, "vault.list_available_context", {})
    serialized = str(discovery)

    assert "identity.full_name" in serialized
    assert "identity.age_over_18" in serialized
    assert "credentials.booking_site" in serialized
    assert "Garry Smith" not in serialized
    assert "garry@example.test" not in serialized
    assert "MAN" not in serialized
    assert "booking-secret-DO-NOT-LEAK" not in serialized
    for item in discovery["items"]:
        assert set(item) >= {"name", "description", "sensitivity"}
        assert "value" not in item


def test_mcp_secret_reveal_is_denied(authority: Authority) -> None:
    server = create_server(authority)
    response = _call(
        server,
        "vault.request_access",
        {
            "agent_id": "travel-agent",
            "agent_name": "Travel Agent",
            "objective": "Book a hotel",
            "purpose": "travel.hotel_booking",
            "items": [{"mode": "reveal", "resource": "credentials.booking_site"}],
        },
    )
    assert response["status"] == "denied"
    assert response["decision"]["outcome"] == "DENY"
    assert response["grant"] is None


def test_mcp_expired_grant_is_rejected(authority: Authority, clock) -> None:
    server = create_server(authority)
    response = _call(
        server,
        "vault.request_access",
        {
            "agent_id": "travel-agent",
            "agent_name": "Travel Agent",
            "objective": "Find a hotel",
            "purpose": "travel.hotel_search",
            "requested_ttl_seconds": 1,
            "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
        },
    )
    clock.advance(timedelta(seconds=2))
    error = _failed_call(
        server,
        "vault.reveal",
        {
            "grant_id": response["grant"]["id"],
            "resource": "preferences.travel.airport",
            "task_id": response["task"]["id"],
        },
    )
    assert error.endswith("grant is expired")
