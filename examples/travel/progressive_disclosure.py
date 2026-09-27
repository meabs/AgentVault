from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from mcp import Client

try:
    from examples.demo_support import call_tool, create_demo_stack, print_json
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from examples.demo_support import call_tool, create_demo_stack, print_json


async def run() -> None:
    _, server, app = create_demo_stack()
    async with Client(server, raise_exceptions=True) as client:
        search = await call_tool(
            client,
            "vault.request_access",
            {
                "agent_id": "travel-agent",
                "agent_name": "Travel Agent",
                "objective": "Find and book a hotel near Edinburgh Waverley",
                "purpose": "travel.hotel_search",
                "items": [{"mode": "reveal", "resource": "preferences.travel.airport"}],
            },
        )
        print_json("1. Search starts with automatic low-risk context", search)

        booking = await call_tool(
            client,
            "vault.request_access",
            {
                "task_id": search["task"]["id"],
                "purpose": "travel.hotel_booking",
                "reason": "Complete the reservation for the hotel selected by the user.",
                "items": [
                    {"mode": "reveal", "resource": "identity.full_name"},
                    {"mode": "reveal", "resource": "identity.email"},
                    {"mode": "prove", "resource": "identity.age_over_18"},
                ],
                "requested_ttl_seconds": 600,
            },
        )
        print_json("2. Booking asks for incremental identity and age authority", booking)
        assert booking["status"] == "approval_required"
        assert booking["grant"] is None

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://pav.local", follow_redirects=True
        ) as browser:
            approved = await browser.post(f"/approvals/{booking['request_id']}/approve")
            approved.raise_for_status()
        print("3. User approves through the local PAV approval screen.")

        status = await call_tool(
            client, "vault.get_request_status", {"request_id": booking["request_id"]}
        )
        print_json("4. MCP client sees the resulting task grant", status)
        grant_id = status["grant"]["id"]
        name = await call_tool(
            client,
            "vault.reveal",
            {"grant_id": grant_id, "resource": "identity.full_name", "task_id": search["task"]["id"]},
        )
        age = await call_tool(
            client,
            "vault.prove",
            {"grant_id": grant_id, "claim": "identity.age_over_18", "task_id": search["task"]["id"]},
        )
        print_json("5. REVEAL returns name; PROVE returns only the boolean age result", {"name": name, "age": age})
        print("ASSERTION: date of birth was not requested or returned; identity was disclosed progressively.")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
