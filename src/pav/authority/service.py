from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import hashlib
import hmac
import secrets
from threading import RLock
from typing import Any

from pav.authority.capabilities import (
    MacOSKeychainSecretProvider,
    MockSecretProvider,
    SecretProvider,
)
from pav.authority.errors import AccessDenied, ApprovalRequired, GrantInvalid
from pav.authority.policy import (
    EmbeddedPolicyDecisionPoint,
    PolicyDecisionPoint,
    PolicyResource,
)
from pav.domain.audit import AuditLog, ChainVerificationResult, verify_audit_chain
from pav.domain.models import (
    AccessRequest,
    AccessRequestItem,
    Agent,
    Attribute,
    ApprovalChallenge,
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


APPROVAL_CODE_MAX_FAILED_ATTEMPTS = 5


class Authority:
    """PAV's policy enforcement point and authority lifecycle."""

    approval_code_ttl = timedelta(minutes=5)

    def __init__(
        self,
        *,
        attributes: dict[str, Attribute] | None = None,
        claims: dict[str, ClaimDefinition] | None = None,
        external_handles: dict[str, ExternalHandle] | None = None,
        policies: Iterable[Policy] = (),
        policy_decision_point: PolicyDecisionPoint | None = None,
        secret_provider: SecretProvider | None = None,
        secret_providers: Mapping[str, SecretProvider] | None = None,
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
        self.policy_decision_point = policy_decision_point or EmbeddedPolicyDecisionPoint(
            self.policies
        )
        self.secret_provider = secret_provider or MockSecretProvider({})
        self.secret_providers: dict[str, SecretProvider] = {
            "mock": self.secret_provider,
            MacOSKeychainSecretProvider.provider_name: MacOSKeychainSecretProvider(),
        }
        self.secret_providers.update(secret_providers or {})
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.agents = self.storage.load_agents()
        self.tasks = self.storage.load_tasks()
        self.requests = self.storage.load_requests()
        self.decisions = self.storage.load_decisions()
        self.approval_challenges = self.storage.load_approval_challenges()
        self.grants = self.storage.load_grants()
        self._audit_log = AuditLog(self.storage.load_audit_events())
        self._approval_lock = RLock()

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

    def _resource(self, name: str) -> PolicyResource | None:
        if name in self.attributes:
            attribute = self.attributes[name]
            return PolicyResource(name, "attribute", attribute.sensitivity)
        if name in self.claims:
            return PolicyResource(name, "claim", Sensitivity.MEDIUM)
        if name in self.external_handles:
            handle = self.external_handles[name]
            return PolicyResource(name, handle.resource_type, handle.sensitivity)
        return None

    def evaluate(self, request: AccessRequest) -> PolicyDecision:
        task = self.tasks.get(request.task_id)
        if task is None or task.agent_id != request.agent_id:
            raise AccessDenied("request is not bound to a known task and agent")

        resources = {
            item.resource: resource
            for item in request.items
            if (resource := self._resource(item.resource)) is not None
        }
        decision = self.policy_decision_point.evaluate(request, resources)
        self.decisions[request.id] = decision
        self.storage.save_decision(decision)
        event_type = {
            DecisionOutcome.ALLOW: AuditEventType.POLICY_ALLOWED,
            DecisionOutcome.DENY: AuditEventType.POLICY_DENIED,
            DecisionOutcome.APPROVAL_REQUIRED: AuditEventType.APPROVAL_REQUESTED,
        }[decision.outcome]
        self._event(
            event_type,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata={
                "reason": "; ".join(decision.reasons)
                if decision.reasons
                else "matched policy"
            },
        )
        return decision

    @staticmethod
    def _approval_code_digest(code: str) -> str:
        return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()

    def create_approval_challenge(
        self, request: AccessRequest | str
    ) -> tuple[str, ApprovalChallenge] | None:
        with self._approval_lock:
            request_id = request.id if isinstance(request, AccessRequest) else request
            decision = self.decisions.get(request_id)
            if decision is None or decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
                raise ValueError("only approval-required requests can receive an approval code")
            if request_id in self.approval_challenges:
                return None
            return self._issue_approval_challenge(request_id)

    def _issue_approval_challenge(self, request_id: str) -> tuple[str, ApprovalChallenge]:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        code = "".join(secrets.choice(alphabet) for _ in range(10))
        challenge = ApprovalChallenge(
            request_id=request_id,
            code_digest=self._approval_code_digest(code),
            expires_at=self._now() + self.approval_code_ttl,
        )
        self.approval_challenges[request_id] = challenge
        self.storage.save_approval_challenge(challenge)
        return code, challenge

    def resend_approval_challenge(
        self, request: AccessRequest | str
    ) -> tuple[str, ApprovalChallenge]:
        """Issue a fresh code for a still-pending approval request."""
        with self._approval_lock:
            request_id = request.id if isinstance(request, AccessRequest) else request
            decision = self.decisions.get(request_id)
            if (
                decision is None
                or decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED
                or decision.approved
                or any(grant.request_id == request_id for grant in self.grants.values())
            ):
                raise ValueError("only still-pending requests can receive a fresh approval code")
            return self._issue_approval_challenge(request_id)

    def approval_code_failure(self, request_id: str, code: str | None) -> str | None:
        challenge = self.approval_challenges.get(request_id)
        if code is None or not code.strip():
            return "missing"
        if challenge is None:
            return "unavailable"
        if challenge.locked_at is not None:
            return "locked_out"
        if challenge.used_at is not None:
            return "already_used"
        if self._now() >= challenge.expires_at:
            return "expired"
        if not hmac.compare_digest(challenge.code_digest, self._approval_code_digest(code)):
            return "incorrect"
        return None

    def consume_approval_code(self, request_id: str, code: str | None) -> str | None:
        with self._approval_lock:
            failure = self.approval_code_failure(request_id, code)
            if failure is not None:
                if failure == "incorrect":
                    challenge = self.approval_challenges[request_id]
                    failed_attempts = challenge.failed_attempts + 1
                    locked_at = (
                        self._now()
                        if failed_attempts >= APPROVAL_CODE_MAX_FAILED_ATTEMPTS
                        else None
                    )
                    updated = challenge.model_copy(
                        update={
                            "failed_attempts": failed_attempts,
                            "locked_at": locked_at,
                            "code_digest": "" if locked_at is not None else challenge.code_digest,
                        }
                    )
                    self.approval_challenges[request_id] = updated
                    self.storage.save_approval_challenge(updated)
                    if locked_at is not None:
                        return "locked_out"
                return failure
            challenge = self.approval_challenges[request_id]
            consumed = challenge.model_copy(update={"used_at": self._now()})
            self.approval_challenges[request_id] = consumed
            self.storage.save_approval_challenge(consumed)
            return None

    def record_approval_code_failure(self, request_id: str, reason: str) -> None:
        request = self.requests.get(request_id)
        if request is None:
            return
        metadata: dict[str, str | int] = {"reason": reason}
        challenge = self.approval_challenges.get(request_id)
        if challenge is not None:
            metadata["failed_attempts"] = challenge.failed_attempts
        self._event(
            AuditEventType.APPROVAL_CODE_REJECTED,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata=metadata,
        )

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

    def deny(self, decision: PolicyDecision) -> PolicyDecision:
        """Record a user's denial without issuing a grant."""
        if decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
            raise ValueError("only approval-required decisions can be denied")
        denied = decision.model_copy(update={"outcome": DecisionOutcome.DENY, "approved": False})
        self.decisions[decision.request.id] = denied
        self.storage.save_decision(denied)
        request = decision.request
        self._event(
            AuditEventType.APPROVAL_DENIED,
            task_id=request.task_id,
            agent_id=request.agent_id,
            request_id=request.id,
            purpose=request.purpose,
            metadata={"item_count": len(request.items)},
        )
        return denied

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
        provider = self.secret_providers.get(handle.provider)
        if provider is None:
            raise AccessDenied(f"no secret provider configured for {handle.provider}")
        if not provider.can_use(handle, destination):
            raise AccessDenied("secret provider rejected the destination")
        execution_handle = provider.execute(handle, "use", destination)
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

    def verify_audit_chain(self) -> ChainVerificationResult:
        """Verify the persisted audit log, including events outside the current task."""

        return verify_audit_chain(self.storage.load_audit_events())
