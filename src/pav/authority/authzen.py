"""Experimental AuthZEN-shaped policy adapter for the PAV PDP seam.

This module proves that PAV's policy decision point can be replaced by an
adapter using the OpenID AuthZEN Authorization API information model. It is
not a production AuthZEN client or a certified AuthZEN implementation: it
does not make network calls, implement an HTTPS binding, authenticate a PDP,
or claim interoperability with a remote deployment.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from typing import Any

from pav.authority.policy import Policy, PolicyResource
from pav.domain.models import AccessRequest, AccessRequestItem, PolicyDecision
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity

AuthZENRequest = dict[str, Any]
AuthZENResponse = Mapping[str, Any]
AuthZENDecisionFunction = Callable[[AuthZENRequest], AuthZENResponse]


def reference_authzen_decision(
    request: AuthZENRequest,
    policies: Sequence[Policy],
) -> dict[str, Any]:
    """Evaluate one AuthZEN-shaped request with the PRD's reference rules."""

    resource = request["resource"]
    action = request["action"]
    context = request["context"]
    resource_properties = resource.get("properties", {})
    resource_type = resource["type"]
    mode = AccessMode(action["name"])
    if resource_type == "unknown":
        return _authzen_response(
            DecisionOutcome.DENY,
            reason=f"unknown resource: {resource['id']}",
        )
    sensitivity = Sensitivity(resource_properties["sensitivity"])
    if mode is AccessMode.REVEAL and resource_type == "secret":
        return _authzen_response(
            DecisionOutcome.DENY,
            reason="secret resources cannot be revealed",
        )

    matches = [
        policy
        for policy in policies
        if policy.matches(
            purpose=context["purpose"],
            mode=mode,
            sensitivity=sensitivity,
            resource_type=resource_type,
        )
    ]
    if not matches:
        return _authzen_response(
            DecisionOutcome.APPROVAL_REQUIRED,
            reason=f"no automatic policy for {resource['id']}",
        )
    decisions = {policy.decision for policy in matches}
    if DecisionOutcome.DENY in decisions:
        outcome = DecisionOutcome.DENY
    elif DecisionOutcome.APPROVAL_REQUIRED in decisions:
        outcome = DecisionOutcome.APPROVAL_REQUIRED
    else:
        outcome = DecisionOutcome.ALLOW
    max_ttl = min(policy.max_ttl for policy in matches)
    max_uses = [policy.max_uses for policy in matches if policy.max_uses is not None]
    return _authzen_response(
        outcome,
        matched_policy_names=[policy.name for policy in matches],
        max_ttl=max_ttl,
        max_uses=min(max_uses) if max_uses else None,
    )


def _authzen_response(
    outcome: DecisionOutcome,
    *,
    reason: str | None = None,
    matched_policy_names: list[str] | None = None,
    max_ttl: timedelta | None = None,
    max_uses: int | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "pav_outcome": outcome.value,
        "matched_policy_names": matched_policy_names or [],
        "max_ttl_seconds": max_ttl.total_seconds() if max_ttl is not None else None,
        "max_uses": max_uses,
    }
    if reason is not None:
        context["reason"] = reason
    return {"decision": outcome is DecisionOutcome.ALLOW, "context": context}


class AuthZENPolicyDecisionPoint:
    """In-process experimental adapter using AuthZEN-shaped messages."""

    def __init__(
        self,
        policies: Sequence[Policy] = (),
        *,
        decision_function: AuthZENDecisionFunction | None = None,
    ) -> None:
        self.policies = list(policies)
        self.decision_function = decision_function or (
            lambda request: reference_authzen_decision(request, self.policies)
        )
        self.last_requests: list[AuthZENRequest] = []

    @staticmethod
    def to_authzen_request(
        request: AccessRequest,
        item: AccessRequestItem,
        resource: PolicyResource | None,
    ) -> AuthZENRequest:
        resource_shape: dict[str, Any] = {
            "type": resource.resource_type if resource is not None else "unknown",
            "id": item.resource,
        }
        if resource is not None:
            resource_shape["properties"] = {"sensitivity": resource.sensitivity.value}
        return {
            "subject": {"type": "agent", "id": request.agent_id},
            "resource": resource_shape,
            "action": {"name": item.mode.value},
            "context": {
                "task_id": request.task_id,
                "purpose": request.purpose,
                "destination": item.destination,
                "requested_ttl_seconds": request.requested_ttl.total_seconds(),
                "requested_max_uses": request.requested_max_uses,
            },
        }

    @staticmethod
    def from_authzen_response(response: AuthZENResponse) -> DecisionOutcome:
        decision = response.get("decision")
        if type(decision) is not bool:
            raise ValueError("AuthZEN response decision must be a boolean")
        context = response.get("context", {})
        if not isinstance(context, Mapping):
            raise ValueError("AuthZEN response context must be an object")
        pav_outcome = context.get("pav_outcome")
        if pav_outcome is not None:
            try:
                return DecisionOutcome(pav_outcome)
            except ValueError as exc:
                raise ValueError("AuthZEN response contains an unknown PAV outcome") from exc
        return DecisionOutcome.ALLOW if decision else DecisionOutcome.DENY

    def evaluate(
        self,
        request: AccessRequest,
        resources: Mapping[str, PolicyResource],
    ) -> PolicyDecision:
        outcomes: list[DecisionOutcome] = []
        matched_names: list[str] = []
        ttl_caps: list[timedelta] = []
        uses_caps: list[int] = []
        reasons: list[str] = []
        for item in request.items:
            authzen_request = self.to_authzen_request(request, item, resources.get(item.resource))
            self.last_requests.append(authzen_request)
            response = self.decision_function(authzen_request)
            outcomes.append(self.from_authzen_response(response))
            context = response.get("context", {})
            if not isinstance(context, Mapping):
                raise ValueError("AuthZEN response context must be an object")
            matched_names.extend(context.get("matched_policy_names", []))
            max_ttl_seconds = context.get("max_ttl_seconds")
            if max_ttl_seconds is not None:
                ttl_caps.append(timedelta(seconds=float(max_ttl_seconds)))
            max_uses = context.get("max_uses")
            if max_uses is not None:
                uses_caps.append(int(max_uses))
            reason = context.get("reason")
            if reason is not None:
                reasons.append(str(reason))

        if DecisionOutcome.DENY in outcomes:
            outcome = DecisionOutcome.DENY
        elif DecisionOutcome.APPROVAL_REQUIRED in outcomes:
            outcome = DecisionOutcome.APPROVAL_REQUIRED
        else:
            outcome = DecisionOutcome.ALLOW
        max_ttl = min([request.requested_ttl, *ttl_caps])
        max_uses = request.requested_max_uses
        if uses_caps:
            max_uses = min([value for value in [max_uses, *uses_caps] if value is not None])
        return PolicyDecision(
            request=request,
            outcome=outcome,
            matched_policy_names=matched_names,
            max_ttl=max_ttl,
            max_uses=max_uses,
            reasons=reasons,
        )


__all__ = [
    "AuthZENPolicyDecisionPoint",
    "AuthZENRequest",
    "AuthZENResponse",
    "reference_authzen_decision",
]
