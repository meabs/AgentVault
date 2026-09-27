from datetime import timedelta

import pytest

from pav.authority.errors import AccessDenied, ApprovalRequired
from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent
from pav.domain.types import AccessMode, AuditEventType, DecisionOutcome, GrantState


def _travel_task(authority: Authority):
    return authority.create_task(
        agent=Agent(id="travel-agent", name="Travel Agent"),
        objective="Book a hotel near Edinburgh Waverley",
    )


def _booking_grant(authority: Authority):
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_booking",
        requested_ttl=timedelta(minutes=10),
        items=[
            AccessRequestItem(mode=AccessMode.REVEAL, resource="identity.full_name"),
            AccessRequestItem(mode=AccessMode.REVEAL, resource="identity.email"),
            AccessRequestItem(mode=AccessMode.PROVE, resource="identity.age_over_18"),
            AccessRequestItem(
                mode=AccessMode.USE,
                resource="credentials.booking_site",
                destination="booking.example",
            ),
        ],
    )
    decision = authority.evaluate(request)
    return task, decision, authority.authorize(authority.approve(decision))


def test_booking_request_requires_approval_before_grant_issuance(authority: Authority) -> None:
    task = _travel_task(authority)
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_booking",
        items=[
            AccessRequestItem(mode=AccessMode.REVEAL, resource="identity.full_name"),
            AccessRequestItem(mode=AccessMode.PROVE, resource="identity.age_over_18"),
            AccessRequestItem(
                mode=AccessMode.USE,
                resource="credentials.booking_site",
                destination="booking.example",
            ),
        ],
    )

    decision = authority.evaluate(request)
    assert decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
    with pytest.raises(ApprovalRequired):
        authority.authorize(decision)

    grant = authority.authorize(authority.approve(decision))
    assert grant.state is GrantState.ACTIVE
    assert grant.max_uses == 1


def test_reveal_returns_the_exact_approved_attribute_value(authority: Authority) -> None:
    task, _, grant = _booking_grant(authority)

    result = authority.reveal(
        grant=grant,
        resource="identity.full_name",
        task=task,
    )

    assert result == {"attribute": "identity.full_name", "value": "Garry Smith"}


def test_prove_returns_only_derived_result_without_source_attribute(authority: Authority) -> None:
    task, _, grant = _booking_grant(authority)

    result = authority.prove(grant=grant, claim="identity.age_over_18", task=task)

    assert result == {"claim": "identity.age_over_18", "result": True}
    assert "identity.date_of_birth" not in repr(result)
    assert "1990-04-12" not in repr(result)


def test_use_returns_opaque_execution_handle_without_secret(authority: Authority, secret_value: str) -> None:
    task, _, grant = _booking_grant(authority)

    result = authority.use(
        grant=grant,
        capability="credentials.booking_site",
        destination="booking.example",
        task=task,
    )

    assert result["status"] == "authorized"
    assert result["execution_handle"].startswith("exec_")
    assert secret_value not in repr(result)


def test_lifecycle_audit_events_are_typed_and_metadata_only(
    authority: Authority,
    secret_value: str,
) -> None:
    task, _, grant = _booking_grant(authority)
    authority.reveal(grant=grant, resource="identity.full_name", task=task)
    authority.prove(grant=grant, claim="identity.age_over_18", task=task)
    authority.use(
        grant=grant,
        capability="credentials.booking_site",
        destination="booking.example",
        task=task,
    )

    event_types = [event.event_type for event in authority.audit(task=task)]
    assert AuditEventType.TASK_CREATED in event_types
    assert AuditEventType.ACCESS_REQUESTED in event_types
    assert AuditEventType.APPROVAL_REQUESTED in event_types
    assert AuditEventType.APPROVAL_GRANTED in event_types
    assert AuditEventType.GRANT_ISSUED in event_types
    assert AuditEventType.ATTRIBUTE_REVEALED in event_types
    assert AuditEventType.CLAIM_PROVED in event_types
    assert AuditEventType.CAPABILITY_USED in event_types
    serialized = repr(authority.audit(task=task))
    assert secret_value not in serialized
    assert "identity.date_of_birth" not in serialized
