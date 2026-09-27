from __future__ import annotations

from datetime import date, timedelta

from pav.adapters.mcp.server import create_server
from pav.adapters.notifications import LogNotifier
from pav.adapters.rest.app import create_app
from pav.authority.capabilities import MockSecretProvider, SecretProvider
from pav.authority.service import Authority
from pav.domain.models import Attribute, ClaimDefinition, ExternalHandle, Policy
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity


DEMO_SECRET = "demo-booking-secret-NEVER-IN-MCP"


def create_demo_stack(
    *,
    external_handle: ExternalHandle | None = None,
    secret_provider: SecretProvider | None = None,
) -> tuple[Authority, object, object]:
    """Build a local demo vault; all workflow operations go through adapters."""

    def age_over_18(values: dict[str, object]) -> bool:
        birthday = values["identity.date_of_birth"]
        assert isinstance(birthday, date)
        today = date.today()
        return (today.year, today.month, today.day) >= (
            birthday.year + 18,
            birthday.month,
            birthday.day,
        )

    handle = external_handle or ExternalHandle(
        name="credentials.booking_site", uri="secret://mock/booking-site"
    )
    provider = secret_provider or MockSecretProvider(
        {"credentials.booking_site": DEMO_SECRET},
        {"credentials.booking_site": {"booking.example"}},
    )
    authority = Authority(
        attributes={
            "identity.full_name": Attribute(
                name="identity.full_name", value="Garry Smith", sensitivity=Sensitivity.HIGH
            ),
            "identity.email": Attribute(
                name="identity.email", value="garry@example.test", sensitivity=Sensitivity.HIGH
            ),
            "identity.date_of_birth": Attribute(
                name="identity.date_of_birth", value=date(1990, 4, 12), sensitivity=Sensitivity.HIGH
            ),
            "preferences.travel.airport": Attribute(
                name="preferences.travel.airport", value="MAN", sensitivity=Sensitivity.LOW
            ),
            "preferences.hotel.quiet_room": Attribute(
                name="preferences.hotel.quiet_room", value=True, sensitivity=Sensitivity.LOW
            ),
        },
        claims={
            "identity.age_over_18": ClaimDefinition(
                name="identity.age_over_18",
                source_attributes=["identity.date_of_birth"],
                evaluator=age_over_18,
            )
        },
        external_handles={
            handle.name: handle
        },
        policies=[
            Policy(
                name="low-risk-travel-context",
                purpose="travel.*",
                mode=AccessMode.REVEAL,
                sensitivity=Sensitivity.LOW,
                decision=DecisionOutcome.ALLOW,
                max_ttl=timedelta(minutes=30),
            ),
            Policy(
                name="capabilities-require-human-approval",
                mode=AccessMode.USE,
                decision=DecisionOutcome.APPROVAL_REQUIRED,
                max_ttl=timedelta(minutes=10),
                max_uses=1,
            ),
        ],
        secret_provider=provider,
    )
    notifier = LogNotifier()
    return authority, create_server(authority, notifier=notifier), create_app(authority, notifier=notifier)


async def call_tool(client, name: str, arguments: dict) -> dict:
    result = await client.call_tool(name, arguments)
    if result.is_error or result.structured_content is None:
        detail = result.content[0].text if result.content else "unknown MCP error"
        raise RuntimeError(f"{name} failed: {detail}")
    return result.structured_content


def print_json(label: str, value: object) -> None:
    import json

    print(f"\n{label}")
    print(json.dumps(value, indent=2, sort_keys=True, default=str))
