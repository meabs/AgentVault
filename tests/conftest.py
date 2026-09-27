from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from pav.authority.capabilities import MockSecretProvider
from pav.authority.service import Authority
from pav.domain.models import (
    Attribute,
    ClaimDefinition,
    ExternalHandle,
    Policy,
)
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity


class MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, amount: timedelta) -> None:
        self.current += amount


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture
def secret_value() -> str:
    return "booking-secret-DO-NOT-LEAK"


@pytest.fixture
def authority(clock: MutableClock, secret_value: str) -> Authority:
    attributes = {
        "identity.full_name": Attribute(
            name="identity.full_name",
            value="Garry Smith",
            sensitivity=Sensitivity.HIGH,
        ),
        "identity.email": Attribute(
            name="identity.email",
            value="garry@example.test",
            sensitivity=Sensitivity.HIGH,
        ),
        "identity.date_of_birth": Attribute(
            name="identity.date_of_birth",
            value=date(1990, 4, 12),
            sensitivity=Sensitivity.HIGH,
        ),
        "preferences.travel.airport": Attribute(
            name="preferences.travel.airport",
            value="MAN",
            sensitivity=Sensitivity.LOW,
        ),
        "preferences.hotel.quiet_room": Attribute(
            name="preferences.hotel.quiet_room",
            value=True,
            sensitivity=Sensitivity.LOW,
        ),
    }

    def age_over_18(values: dict[str, object]) -> bool:
        dob = values["identity.date_of_birth"]
        assert isinstance(dob, date)
        today = date(2026, 9, 27)
        years = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return years >= 18

    claims = {
        "identity.age_over_18": ClaimDefinition(
            name="identity.age_over_18",
            source_attributes=["identity.date_of_birth"],
            evaluator=age_over_18,
        )
    }
    handles = {
        "credentials.booking_site": ExternalHandle(
            name="credentials.booking_site",
            uri="secret://mock/booking-site",
        )
    }
    policies = [
        Policy(
            name="low-risk-travel-preferences",
            purpose="travel.*",
            mode=AccessMode.REVEAL,
            sensitivity=Sensitivity.LOW,
            decision=DecisionOutcome.ALLOW,
            max_ttl=timedelta(minutes=30),
        ),
        Policy(
            name="secrets-require-approval",
            mode=AccessMode.USE,
            decision=DecisionOutcome.APPROVAL_REQUIRED,
            max_ttl=timedelta(minutes=10),
            max_uses=1,
        ),
        Policy(
            name="raw-secrets-never-reveal",
            mode=AccessMode.REVEAL,
            resource_type="secret",
            decision=DecisionOutcome.DENY,
            max_ttl=timedelta(minutes=1),
        ),
    ]
    return Authority(
        attributes=attributes,
        claims=claims,
        external_handles=handles,
        policies=policies,
        secret_provider=MockSecretProvider(
            {"credentials.booking_site": secret_value},
            {"credentials.booking_site": {"booking.example"}},
        ),
        clock=clock,
    )
