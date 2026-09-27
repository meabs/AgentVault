from datetime import timedelta

import pytest

from pav.authority.errors import AccessDenied, GrantInvalid
from pav.authority.service import Authority
from pav.domain.models import (
    AccessRequestItem,
    Agent,
    Grant,
    GrantPermission,
    InvalidGrantTransition,
    Policy,
)
from pav.domain.types import (
    AccessMode,
    DecisionOutcome,
    GrantState,
    Sensitivity,
)

from tests.unit.test_phase0_lifecycle import _booking_grant, _travel_task


def test_reveal_of_resource_not_on_grant_allow_list_is_denied(authority: Authority) -> None:
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="preferences.travel.airport")],
    )
    grant = authority.authorize(authority.evaluate(request))

    with pytest.raises(AccessDenied):
        authority.reveal(grant=grant, resource="identity.email", task=task)


def test_grant_issued_for_task_a_cannot_be_used_under_task_b(authority: Authority) -> None:
    task_a = _travel_task(authority)
    task_b = authority.create_task(
        agent=Agent(id="research-agent", name="Research Agent"),
        objective="Research unrelated restaurants",
    )
    request = authority.request_access(
        task=task_a,
        purpose="travel.hotel_search",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="preferences.travel.airport")],
    )
    grant = authority.authorize(authority.evaluate(request))

    with pytest.raises(AccessDenied):
        authority.reveal(
            grant=grant,
            resource="preferences.travel.airport",
            task=task_b,
        )


def test_expired_grant_cannot_be_used(authority: Authority, clock) -> None:
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        requested_ttl=timedelta(seconds=1),
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="preferences.travel.airport")],
    )
    grant = authority.authorize(authority.evaluate(request))
    clock.advance(timedelta(seconds=2))

    with pytest.raises(GrantInvalid):
        authority.reveal(grant=grant, resource="preferences.travel.airport", task=task)
    assert grant.state is GrantState.EXPIRED


def test_grant_cannot_be_reused_past_max_uses(authority: Authority) -> None:
    task, _, grant = _booking_grant(authority)
    authority.use(
        grant=grant,
        capability="credentials.booking_site",
        destination="booking.example",
        task=task,
    )

    with pytest.raises(GrantInvalid):
        authority.use(
            grant=grant,
            capability="credentials.booking_site",
            destination="booking.example",
            task=task,
        )
    assert grant.state is GrantState.EXHAUSTED


def test_use_destination_substitution_is_denied(authority: Authority) -> None:
    task, _, grant = _booking_grant(authority)

    with pytest.raises(AccessDenied):
        authority.use(
            grant=grant,
            capability="credentials.booking_site",
            destination="evil.example",
            task=task,
        )


def test_revoked_grant_cannot_be_used_before_natural_expiry(authority: Authority) -> None:
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="preferences.travel.airport")],
    )
    grant = authority.authorize(authority.evaluate(request))
    authority.revoke(grant=grant)

    with pytest.raises(GrantInvalid):
        authority.reveal(grant=grant, resource="preferences.travel.airport", task=task)


def test_secret_resource_never_reveals_even_when_policy_attempts_to_allow_it(authority: Authority, clock) -> None:
    authority.policies.append(
        Policy(
            name="malicious-secret-reveal-allow",
            mode=AccessMode.REVEAL,
            resource_type="secret",
            decision=DecisionOutcome.ALLOW,
            max_ttl=timedelta(minutes=30),
        )
    )
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_booking",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="credentials.booking_site")],
    )
    decision = authority.evaluate(request)
    assert decision.outcome is DecisionOutcome.DENY
    with pytest.raises(AccessDenied):
        authority.authorize(decision)

    manually_constructed_grant = Grant(
        agent_id=task.agent_id,
        task_id=task.id,
        purpose=request.purpose,
        permissions=[
            GrantPermission(
                mode=AccessMode.REVEAL,
                resource="credentials.booking_site",
            )
        ],
        issued_at=clock.current,
        expires_at=clock.current + timedelta(minutes=5),
    )
    with pytest.raises(AccessDenied):
        authority.reveal(
            grant=manually_constructed_grant,
            resource="credentials.booking_site",
            task=task,
        )


def test_terminal_grant_states_cannot_transition_back_to_active(authority: Authority) -> None:
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_booking",
        items=[
            AccessRequestItem(
                mode=AccessMode.USE,
                resource="credentials.booking_site",
                destination="booking.example",
            )
        ],
    )
    base = authority.authorize(authority.approve(authority.evaluate(request)))

    for terminal_state in (GrantState.REVOKED, GrantState.EXPIRED, GrantState.EXHAUSTED):
        grant = base.model_copy(deep=True)
        grant.transition(terminal_state)
        with pytest.raises(InvalidGrantTransition):
            grant.transition(GrantState.ACTIVE)
