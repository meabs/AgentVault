from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .types import (
    AccessMode,
    AuditEventType,
    DecisionOutcome,
    GrantState,
    Sensitivity,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Attribute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    value: Any
    sensitivity: Sensitivity
    schema_type: str | None = None
    provenance: str | None = None
    verified: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ClaimDefinition(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str
    source_attributes: list[str]
    evaluator: Callable[[Mapping[str, Any]], Any] | None = None


class ExternalHandle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    uri: str
    sensitivity: Sensitivity = Sensitivity.SECRET
    resource_type: str = "secret"


class Agent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    protocol: str | None = None
    runtime: str | None = None
    trust_metadata: dict[str, str] = Field(default_factory=dict)


class Task(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"task_{uuid4().hex}")
    objective: str
    agent_id: str
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


class AccessRequestItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: AccessMode
    resource: str
    destination: str | None = None


class AccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"req_{uuid4().hex}")
    task_id: str
    agent_id: str
    purpose: str
    items: list[AccessRequestItem]
    requested_ttl: timedelta = timedelta(minutes=15)
    requested_max_uses: int | None = None
    created_at: datetime = Field(default_factory=utc_now)
    reason: str | None = None


class GrantPermission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: AccessMode
    resource: str
    destination: str | None = None


class InvalidGrantTransition(ValueError):
    pass


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(default_factory=lambda: f"grant_{uuid4().hex}")
    agent_id: str
    task_id: str
    purpose: str
    request_id: str | None = None
    permissions: list[GrantPermission]
    issued_at: datetime
    expires_at: datetime
    max_uses: int | None = None
    uses: int = 0
    state: GrantState = GrantState.ACTIVE

    def transition(self, new_state: GrantState) -> None:
        terminal = {GrantState.REVOKED, GrantState.EXPIRED, GrantState.EXHAUSTED}
        allowed: dict[GrantState, set[GrantState]] = {
            GrantState.REQUESTED: {
                GrantState.DENIED,
                GrantState.APPROVAL_REQUIRED,
                GrantState.APPROVED,
            },
            GrantState.APPROVAL_REQUIRED: {
                GrantState.DENIED,
                GrantState.APPROVED,
            },
            GrantState.APPROVED: {GrantState.ACTIVE},
            GrantState.ACTIVE: terminal,
            GrantState.DENIED: set(),
            GrantState.REVOKED: set(),
            GrantState.EXPIRED: set(),
            GrantState.EXHAUSTED: set(),
        }
        if self.state in terminal or new_state not in allowed[self.state]:
            raise InvalidGrantTransition(
                f"cannot transition grant from {self.state} to {new_state}"
            )
        self.state = new_state


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    purpose: str | None = None
    mode: AccessMode | None = None
    sensitivity: Sensitivity | None = None
    resource_type: str | None = None
    decision: DecisionOutcome
    max_ttl: timedelta = timedelta(minutes=15)
    max_uses: int | None = None

    def matches(
        self,
        *,
        purpose: str,
        mode: AccessMode,
        sensitivity: Sensitivity,
        resource_type: str,
    ) -> bool:
        return all(
            (
                self.purpose is None or fnmatchcase(purpose, self.purpose),
                self.mode is None or self.mode == mode,
                self.sensitivity is None or self.sensitivity is sensitivity,
                self.resource_type is None or self.resource_type == resource_type,
            )
        )


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: AccessRequest
    outcome: DecisionOutcome
    matched_policy_names: list[str] = Field(default_factory=list)
    max_ttl: timedelta
    max_uses: int | None = None
    approved: bool = False


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"event_{uuid4().hex}")
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=utc_now)
    task_id: str | None = None
    agent_id: str | None = None
    request_id: str | None = None
    grant_id: str | None = None
    purpose: str | None = None
    resource: str | None = None
    mode: AccessMode | None = None
    destination: str | None = None
    metadata: dict[str, str | int | bool | None] = Field(default_factory=dict)


__all__ = [
    "AccessRequest",
    "AccessRequestItem",
    "Agent",
    "Attribute",
    "AuditEvent",
    "ClaimDefinition",
    "ExternalHandle",
    "Grant",
    "GrantPermission",
    "InvalidGrantTransition",
    "Policy",
    "PolicyDecision",
    "Task",
]
