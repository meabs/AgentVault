from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from mcp import Client

try:
    from examples.demo_support import DEMO_SECRET, call_tool, create_demo_stack, print_json
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from examples.demo_support import DEMO_SECRET, call_tool, create_demo_stack, print_json


async def run() -> None:
    _, server, app = create_demo_stack()
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
        print_json("3. vault.use returns an opaque execution handle", used)
        serialized = str(used)
        assert DEMO_SECRET not in serialized
        assert "execution_handle" in used
        print("ASSERTION: credential value is absent from the MCP response and never enters caller context.")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
