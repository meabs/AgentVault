from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import Client

try:
    from examples.demo_support import call_tool, create_demo_stack, print_json
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from examples.demo_support import call_tool, create_demo_stack, print_json


async def run() -> None:
    _, server, _ = create_demo_stack()
    async with Client(server, raise_exceptions=True) as client:
        context = await call_tool(client, "vault.list_available_context", {})
        print_json("1. MCP discovery returns safe metadata only", context)

        request = await call_tool(
            client,
            "vault.request_access",
            {
                "agent_id": "travel-agent",
                "agent_name": "Travel Agent",
                "objective": "Find a hotel near Edinburgh Waverley",
                "purpose": "travel.hotel_search",
                "items": [
                    {"mode": "reveal", "resource": "preferences.travel.airport"},
                    {"mode": "reveal", "resource": "preferences.hotel.quiet_room"},
                ],
            },
        )
        print_json("2. Search request is auto-allowed (no approval required)", request)
        assert request["status"] == "granted"

        revealed = await call_tool(
            client,
            "vault.reveal",
            {
                "grant_id": request["grant"]["id"],
                "resource": "preferences.travel.airport",
                "task_id": request["task"]["id"],
            },
        )
        print_json("3. Agent receives only the low-risk preference it requested", revealed)
        print("ASSERTION: travel search completed without a human approval step.")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
