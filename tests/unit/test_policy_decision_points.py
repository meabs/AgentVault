from datetime import timedelta

import pytest

from pav.authority.authzen import AuthZENPolicyDecisionPoint
from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent, Attribute, ExternalHandle, Policy
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity


def _authority(
    *,
    policy_decision_point=None,
    attributes=None,
    external_handles=None,
    policies=(),
) -> Authority:
    return Authority(
        attributes=attributes,
        external_handles=external_handles,
        policies=policies,
        policy_decision_point=policy_decision_point,
    )


def _fr16_policies() -> list[Policy]:
    return [
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


def test_authzen_translation_uses_the_authorization_api_request_shape() -> None:
    policies = _fr16_policies()
    adapter = AuthZENPolicyDecisionPoint(policies)
    authority = _authority(
        policy_decision_point=adapter,
        attributes={
            "preferences.travel.airport": Attribute(
                name="preferences.travel.airport",
                value="MAN",
                sensitivity=Sensitivity.LOW,
            )
        },
        policies=policies,
    )
    task = authority.create_task(
        agent=Agent(id="travel-agent", name="Travel Agent"),
        objective="Search for a hotel",
    )
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        requested_ttl=timedelta(minutes=15),
        items=[
            AccessRequestItem(
                mode=AccessMode.REVEAL,
                resource="preferences.travel.airport",
            )
        ],
    )

    decision = authority.evaluate(request)
    wire_request = adapter.last_requests[-1]

    assert decision.outcome is DecisionOutcome.ALLOW
    assert wire_request == {
        "subject": {"type": "agent", "id": "travel-agent"},
        "resource": {
            "type": "attribute",
            "id": "preferences.travel.airport",
            "properties": {"sensitivity": "low"},
        },
        "action": {"name": "reveal"},
        "context": {
            "task_id": task.id,
            "purpose": "travel.hotel_search",
            "destination": None,
            "requested_ttl_seconds": 900.0,
            "requested_max_uses": None,
        },
    }


@pytest.mark.parametrize(
    ("item", "resource_kind", "expected"),
    [
        (
            AccessRequestItem(
                mode=AccessMode.REVEAL,
                resource="preferences.travel.airport",
            ),
            "attribute",
            DecisionOutcome.ALLOW,
        ),
        (
            AccessRequestItem(
                mode=AccessMode.USE,
                resource="credentials.booking_site",
                destination="booking.example",
            ),
            "secret",
            DecisionOutcome.APPROVAL_REQUIRED,
        ),
        (
            AccessRequestItem(
                mode=AccessMode.REVEAL,
                resource="credentials.booking_site",
            ),
            "secret",
            DecisionOutcome.DENY,
        ),
    ],
)
def test_authzen_adapter_matches_embedded_pdp_for_fr16_policies(
    item: AccessRequestItem,
    resource_kind: str,
    expected: DecisionOutcome,
) -> None:
    policies = _fr16_policies()
    attributes = {
        "preferences.travel.airport": Attribute(
            name="preferences.travel.airport",
            value="MAN",
            sensitivity=Sensitivity.LOW,
        )
    }
    handles = {
        "credentials.booking_site": ExternalHandle(
            name="credentials.booking_site",
            uri="secret://mock/booking-site",
        )
    }
    embedded = _authority(
        attributes=attributes,
        external_handles=handles,
        policies=policies,
    )
    authzen = _authority(
        policy_decision_point=AuthZENPolicyDecisionPoint(policies),
        attributes=attributes,
        external_handles=handles,
        policies=policies,
    )

    embedded_task = embedded.create_task(
        agent=Agent(id="travel-agent", name="Travel Agent"),
        objective="Exercise a policy",
    )
    authzen_task = authzen.create_task(
        agent=Agent(id="travel-agent", name="Travel Agent"),
        objective="Exercise a policy",
    )
    embedded_request = embedded.request_access(
        task=embedded_task,
        purpose="travel.hotel_search" if resource_kind == "attribute" else "travel.hotel_booking",
        items=[item],
    )
    authzen_request = authzen.request_access(
        task=authzen_task,
        purpose=embedded_request.purpose,
        items=[item],
    )

    embedded_decision = embedded.evaluate(embedded_request)
    authzen_decision = authzen.evaluate(authzen_request)

    assert embedded_decision.outcome is expected
    assert authzen_decision.outcome is embedded_decision.outcome
    assert authzen_decision.matched_policy_names == embedded_decision.matched_policy_names
    assert authzen_decision.max_ttl == embedded_decision.max_ttl
    assert authzen_decision.max_uses == embedded_decision.max_uses


def test_authority_can_run_a_low_risk_lifecycle_through_authzen_adapter() -> None:
    policies = _fr16_policies()
    authority = _authority(
        policy_decision_point=AuthZENPolicyDecisionPoint(policies),
        attributes={
            "preferences.travel.airport": Attribute(
                name="preferences.travel.airport",
                value="MAN",
                sensitivity=Sensitivity.LOW,
            )
        },
        policies=policies,
    )
    task = authority.create_task(
        agent=Agent(id="travel-agent", name="Travel Agent"),
        objective="Search for a hotel near Edinburgh Waverley",
    )
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        items=[
            AccessRequestItem(
                mode=AccessMode.REVEAL,
                resource="preferences.travel.airport",
            )
        ],
    )

    grant = authority.authorize(authority.evaluate(request))

    assert authority.reveal(
        grant=grant,
        resource="preferences.travel.airport",
        task=task,
    ) == {"attribute": "preferences.travel.airport", "value": "MAN"}
