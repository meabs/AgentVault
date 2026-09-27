from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any

from pav.authority.capabilities import MockSecretProvider, SecretProvider
from pav.authority.errors import AccessDenied, ApprovalRequired, GrantInvalid
from pav.domain.audit import AuditLog
from pav.domain.models import (
    AccessRequest,
    AccessRequestItem,
    Agent,
    Attribute,
    AuditEvent,
    ClaimDefinition,
    ExternalHandle,
    Grant,
    GrantPermission,
    Policy,
    PolicyDecision,
    Task,
)
from pav.domain.types import (
    AccessMode,
    AuditEventType,
    DecisionOutcome,
    GrantState,
    Sensitivity,
)
from pav.persistence import AuthorityStorage, InMemoryStorage


@dataclass(frozen=True)
class _Resource:
    name: str
    resource_type: str
    sensitivity: Sensitivity


class Authority:
    """The Phase 0 policy decision point and policy enforcement point."""

    def __init__(
        self,
        *,
        attributes: dict[str, Attribute] | None = None,
        claims: dict[str, ClaimDefinition] | None = None,
        external_handles: dict[str, ExternalHandle] | None = None,
        policies: Iterable[Policy] = (),
        secret_provider: SecretProvider | None = None,
        clock: Callable[[], datetime] | None = None,
        storage: AuthorityStorage | None = None,
    ) -> None:
        self.storage = storage or InMemoryStorage()
        for attribute in (attributes or {}).values():
            self.storage.save_attribute(attribute)
        for claim in (claims or {}).values():
            self.storage.save_claim(claim)
        for handle in (external_handles or {}).values():
            self.storage.save_external_handle(handle)
        self.attributes = self.storage.load_attributes()
        evaluators = {
            name: claim.evaluator
            for name, claim in (claims or {}).items()
            if claim.evaluator is not None
        }
        self.claims = self.storage.load_claims(evaluators)
        self.external_handles = self.storage.load_external_handles()
        self.policies = list(policies)
        self.secret_provider = secret_provider or MockSecretProvider({})
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.agents = self.storage.load_agents()
        self.tasks = self.storage.load_tasks()
        self.requests = self.storage.load_requests()
        self.decisions = self.storage.load_decisions()
        self.grants = self.storage.load_grants()
        self._audit_log = AuditLog(self.storage.load_audit_events())

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _event(self, event_type: AuditEventType, **fields: Any) -> AuditEvent:
        event = AuditEvent(event_type=event_type, timestamp=self._now(), **fields)
        event = self._audit_log.append(event)
        self.storage.append_audit_event(event)
        return event

    def register_agent(self, agent: Agent) -> Agent:
        self.agents[agent.id] = agent
        self.storage.save_agent(agent)
        return agent

    def create_task(
        self,
        *,
        agent: Agent | str,
        objective: str,
        task_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> Task:
        if isinstance(agent, Agent):
            self.register_agent(agent)
            agent_id = agent.id
        else:
            agent_id = agent
            if agent_id not in self.agents:
                raise ValueError(f"unknown agent: {agent_id}")
        task = Task(
            id=task_id or Task.model_fields["id"].default_factory(),
            objective=objective,
            agent_id=agent_id,
            created_at=self._now(),
            expires_at=expires_at,
        )
        self.tasks[task.id] = task
        self.storage.save_task(task)
        self._event(
            AuditEventType.TASK_CREATED,
            task_id=task.id,
            agent_id=task.agent_id,
            metadata={"objective": task.objective},
        )
        return task

    def request_access(
        self,
        *,
        task: Task,
        purpose: str,
        items: Iterable[AccessRequestItem | dict[str, Any]],
        requested_ttl: timedelta = timedelta(minutes=15),
        max_uses: int | None = None,
        reason: str | None = None,
    ) -> AccessRequest:
        if task.id not in self.tasks:
            raise ValueError(f"unknown task: {task.id}")
        request = AccessRequest(
            task_id=task.id,
            agent_id=task.agent_id,
            purpose=purpose,
            items=[
                item if isinstance(item, AccessRequestItem) else AccessRequestItem.model_validate(item)
                for item in items
            ],
            requested_ttl=requested_ttl,
            requested_max_uses=max_uses,
            created_at=self._now(),
            reason=reason,
        )
        self.requests[request.id] = request
        self.storage.save_request(request)
        self._event(
            AuditEventType.ACCESS_REQUESTED,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata={
                "item_count": len(request.items),
                "resources": ",".join(item.resource for item in request.items),
            },
        )
        return request

    def _resource(self, name: str) -> _Resource | None:
        if name in self.attributes:
            attribute = self.attributes[name]
            return _Resource(name, "attribute", attribute.sensitivity)
        if name in self.claims:
            return _Resource(name, "claim", Sensitivity.MEDIUM)
        if name in self.external_handles:
            handle = self.external_handles[name]
            return _Resource(name, handle.resource_type, handle.sensitivity)
        return None

    def evaluate(self, request: AccessRequest) -> PolicyDecision:
        task = self.tasks.get(request.task_id)
        if task is None or task.agent_id != request.agent_id:
            raise AccessDenied("request is not bound to a known task and agent")

        outcomes: list[DecisionOutcome] = []
        matched_names: list[str] = []
        ttl_caps: list[timedelta] = []
        uses_caps: list[int] = []
        reasons: list[str] = []
        for item in request.items:
            resource = self._resource(item.resource)
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
        ttl = min([request.requested_ttl, *ttl_caps])
        max_uses = request.requested_max_uses
        if uses_caps:
            max_uses = min([value for value in [max_uses, *uses_caps] if value is not None])
        decision = PolicyDecision(
            request=request,
            outcome=outcome,
            matched_policy_names=matched_names,
            max_ttl=ttl,
            max_uses=max_uses,
        )
        self.decisions[request.id] = decision
        self.storage.save_decision(decision)
        event_type = {
            DecisionOutcome.ALLOW: AuditEventType.POLICY_ALLOWED,
            DecisionOutcome.DENY: AuditEventType.POLICY_DENIED,
            DecisionOutcome.APPROVAL_REQUIRED: AuditEventType.APPROVAL_REQUESTED,
        }[outcome]
        self._event(
            event_type,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata={"reason": "; ".join(reasons) if reasons else "matched policy"},
        )
        return decision

    def approve(self, decision: PolicyDecision) -> PolicyDecision:
        if decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
            raise ValueError("only approval-required decisions can be approved")
        if decision.approved:
            return decision
        approved = decision.model_copy(update={"approved": True})
        self.decisions[decision.request.id] = approved
        self.storage.save_decision(approved)
        request = decision.request
        self._event(
            AuditEventType.APPROVAL_GRANTED,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata={"item_count": len(request.items)},
        )
        return approved

    def authorize(self, decision: PolicyDecision) -> Grant:
        if decision.outcome is DecisionOutcome.DENY:
            raise AccessDenied("policy denied the access request")
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED and not decision.approved:
            raise ApprovalRequired("user approval is required before grant issuance")
        return self.issue_grant(decision)

    def issue_grant(self, decision: PolicyDecision) -> Grant:
        if decision.outcome is DecisionOutcome.DENY:
            raise AccessDenied("policy denied the access request")
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED and not decision.approved:
            raise ApprovalRequired("user approval is required before grant issuance")
        request = decision.request
        issued_at = self._now()
        grant = Grant(
            agent_id=request.agent_id,
            task_id=request.task_id,
            purpose=request.purpose,
            request_id=request.id,
            permissions=[
                GrantPermission(
                    mode=item.mode,
                    resource=item.resource,
                    destination=item.destination,
                )
                for item in request.items
            ],
            issued_at=issued_at,
            expires_at=issued_at + decision.max_ttl,
            max_uses=decision.max_uses,
        )
        self.grants[grant.id] = grant
        self.storage.save_grant(grant)
        self._event(
            AuditEventType.GRANT_ISSUED,
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            request_id=request.id,
            grant_id=grant.id,
            purpose=grant.purpose,
            metadata={"permission_count": len(grant.permissions)},
        )
        return grant

    def _enforce(
        self,
        *,
        grant: Grant,
        mode: AccessMode,
        resource: str,
        task: Task | str | None = None,
        agent: Agent | str | None = None,
        purpose: str | None = None,
        destination: str | None = None,
    ) -> GrantPermission:
        if grant.id in self.grants:
            grant = self.grants[grant.id]
        now = self._now()
        if grant.state is GrantState.ACTIVE and now >= grant.expires_at:
            grant.transition(GrantState.EXPIRED)
            self.storage.save_grant(grant)
            self._event(
                AuditEventType.GRANT_EXPIRED,
                task_id=grant.task_id,
                agent_id=grant.agent_id,
                grant_id=grant.id,
                purpose=grant.purpose,
            )
        if grant.state is not GrantState.ACTIVE:
            raise GrantInvalid(f"grant is {grant.state}")
        task_id = task.id if isinstance(task, Task) else task
        if task_id is not None and task_id != grant.task_id:
            raise AccessDenied("grant is bound to a different task")
        agent_id = agent.id if isinstance(agent, Agent) else agent
        if agent_id is not None and agent_id != grant.agent_id:
            raise AccessDenied("grant is bound to a different agent")
        if purpose is not None and purpose != grant.purpose:
            raise AccessDenied("grant is bound to a different purpose")
        permission = next(
            (
                permission
                for permission in grant.permissions
                if permission.mode is mode and fnmatchcase(resource, permission.resource)
            ),
            None,
        )
        if permission is None:
            raise AccessDenied("resource and mode are not on the grant allow-list")
        if mode is AccessMode.USE and permission.destination != destination:
            raise AccessDenied("destination does not match the grant constraint")
        if mode is AccessMode.REVEAL:
            descriptor = self._resource(resource)
            if descriptor is None or descriptor.resource_type == "secret":
                raise AccessDenied("secret resources cannot be revealed")
        return permission

    def reveal(
        self,
        *,
        grant: Grant,
        resource: str,
        task: Task | str | None = None,
        agent: Agent | str | None = None,
        purpose: str | None = None,
    ) -> dict[str, Any]:
        self._enforce(
            grant=grant,
            mode=AccessMode.REVEAL,
            resource=resource,
            task=task,
            agent=agent,
            purpose=purpose,
        )
        attribute = self.attributes.get(resource)
        if attribute is None:
            raise AccessDenied("reveal only supports attributes")
        result = {"attribute": resource, "value": attribute.value}
        self._event(
            AuditEventType.ATTRIBUTE_REVEALED,
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            grant_id=grant.id,
            purpose=grant.purpose,
            resource=resource,
            mode=AccessMode.REVEAL,
        )
        return result

    def prove(
        self,
        *,
        grant: Grant,
        claim: str,
        task: Task | str | None = None,
        agent: Agent | str | None = None,
        purpose: str | None = None,
    ) -> dict[str, Any]:
        self._enforce(
            grant=grant,
            mode=AccessMode.PROVE,
            resource=claim,
            task=task,
            agent=agent,
            purpose=purpose,
        )
        definition = self.claims.get(claim)
        if definition is None or definition.evaluator is None:
            raise AccessDenied("unknown claim or unavailable claim evaluator")
        source_values = {
            source: self.attributes[source].value for source in definition.source_attributes
        }
        result = {"claim": claim, "result": definition.evaluator(source_values)}
        self._event(
            AuditEventType.CLAIM_PROVED,
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            grant_id=grant.id,
            purpose=grant.purpose,
            resource=claim,
            mode=AccessMode.PROVE,
        )
        return result

    def use(
        self,
        *,
        grant: Grant,
        capability: str,
        destination: str,
        task: Task | str | None = None,
        agent: Agent | str | None = None,
        purpose: str | None = None,
    ) -> dict[str, str]:
        self._enforce(
            grant=grant,
            mode=AccessMode.USE,
            resource=capability,
            task=task,
            agent=agent,
            purpose=purpose,
            destination=destination,
        )
        handle = self.external_handles.get(capability)
        if handle is None:
            raise AccessDenied("unknown capability")
        if not self.secret_provider.can_use(handle, destination):
            raise AccessDenied("secret provider rejected the destination")
        execution_handle = self.secret_provider.execute(handle, "use", destination)
        grant.uses += 1
        if grant.max_uses is not None and grant.uses >= grant.max_uses:
            grant.transition(GrantState.EXHAUSTED)
        self.storage.save_grant(grant)
        self._event(
            AuditEventType.CAPABILITY_USED,
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            grant_id=grant.id,
            purpose=grant.purpose,
            resource=capability,
            mode=AccessMode.USE,
            destination=destination,
            metadata={"uses": grant.uses},
        )
        return {"status": "authorized", "execution_handle": execution_handle}

    def revoke(self, *, grant: Grant) -> None:
        if grant.id in self.grants:
            grant = self.grants[grant.id]
        if grant.state is GrantState.ACTIVE:
            grant.transition(GrantState.REVOKED)
        elif grant.state in {GrantState.REVOKED, GrantState.EXPIRED, GrantState.EXHAUSTED}:
            return
        else:
            raise GrantInvalid(f"cannot revoke grant in state {grant.state}")
        self.storage.save_grant(grant)
        self._event(
            AuditEventType.GRANT_REVOKED,
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            grant_id=grant.id,
            purpose=grant.purpose,
        )

    def audit(self, *, task: Task | str | None = None) -> list[AuditEvent]:
        if task is None:
            return self._audit_log.all()
        task_id = task.id if isinstance(task, Task) else task
        return self._audit_log.for_task(task_id)
