from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from pav.domain.models import AccessRequest, Policy, PolicyDecision
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity


@dataclass(frozen=True)
class PolicyResource:
    """Non-sensitive metadata a PDP needs to evaluate a PAV resource."""

    name: str
    resource_type: str
    sensitivity: Sensitivity


class PolicyDecisionPoint(Protocol):
    """The decision seam between Authority's enforcement and policy evaluation."""

    def evaluate(
        self,
        request: AccessRequest,
        resources: Mapping[str, PolicyResource],
    ) -> PolicyDecision:
        """Return the policy decision for a request and its resource metadata."""


class EmbeddedPolicyDecisionPoint:
    """The original deterministic, in-process PAV policy evaluator."""

    def __init__(self, policies: list[Policy] | Iterable[Policy] = ()) -> None:
        self.policies = policies if isinstance(policies, list) else list(policies)

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
            resource = resources.get(item.resource)
            if resource is None:
                outcomes.append(DecisionOutcome.DENY)
                reasons.append(f"unknown resource: {item.resource}")
                continue
            if item.mode is AccessMode.REVEAL and resource.resource_type == "secret":
                outcomes.append(DecisionOutcome.DENY)
                reasons.append("secret resources cannot be revealed")
                continue
            matches = [
                policy
                for policy in self.policies
                if policy.matches(
                    purpose=request.purpose,
                    mode=item.mode,
                    sensitivity=resource.sensitivity,
                    resource_type=resource.resource_type,
                )
            ]
            matched_names.extend(policy.name for policy in matches)
            if not matches:
                outcomes.append(DecisionOutcome.APPROVAL_REQUIRED)
                reasons.append(f"no automatic policy for {item.resource}")
                continue
            item_decisions = {policy.decision for policy in matches}
            if DecisionOutcome.DENY in item_decisions:
                outcomes.append(DecisionOutcome.DENY)
            elif DecisionOutcome.APPROVAL_REQUIRED in item_decisions:
                outcomes.append(DecisionOutcome.APPROVAL_REQUIRED)
            else:
                outcomes.append(DecisionOutcome.ALLOW)
            ttl_caps.extend(policy.max_ttl for policy in matches)
            uses_caps.extend(policy.max_uses for policy in matches if policy.max_uses is not None)

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
    "EmbeddedPolicyDecisionPoint",
    "Policy",
    "PolicyDecision",
    "PolicyDecisionPoint",
    "PolicyResource",
]
