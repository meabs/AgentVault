from datetime import timedelta

from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent, Attribute, Policy
from pav.domain.types import AccessMode, AuditEventType, DecisionOutcome, Sensitivity


def test_low_risk_travel_reveal_is_auto_allowed_and_issued_as_active_grant() -> None:
    agent = Agent(id="travel-agent", name="Travel Agent")
    authority = Authority(
        attributes={
            "preferences.travel.airport": Attribute(
                name="preferences.travel.airport",
                value="MAN",
                sensitivity=Sensitivity.LOW,
            )
        },
        policies=[
            Policy(
                name="low-risk-travel-preferences",
                purpose="travel.*",
                mode=AccessMode.REVEAL,
                sensitivity=Sensitivity.LOW,
                decision=DecisionOutcome.ALLOW,
                max_ttl=timedelta(minutes=30),
            )
        ],
    )
    task = authority.create_task(
        agent=agent,
        objective="Search for a hotel near Edinburgh Waverley",
    )
    request = authority.request_access(
        task=task,
        purpose="travel.hotel_search",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="preferences.travel.airport")],
    )

    decision = authority.evaluate(request)
    grant = authority.authorize(decision)

    assert decision.outcome is DecisionOutcome.ALLOW
    assert grant.state.value == "active"
    assert all(
        event.event_type is not AuditEventType.APPROVAL_REQUESTED
        for event in authority.audit(task=task)
    )
    assert authority.reveal(grant=grant, resource="preferences.travel.airport") == {
        "attribute": "preferences.travel.airport",
        "value": "MAN",
    }
