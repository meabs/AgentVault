from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from pav.authority.errors import AccessDenied, ApprovalRequired, AuthorityError, GrantInvalid
from pav.authority.service import Authority
from pav.domain.models import AccessRequest, AccessRequestItem, Agent, Grant, PolicyDecision, Task
from pav.domain.types import DecisionOutcome
from pav.persistence import SQLiteStorage


class CreateTaskBody(BaseModel):
    agent: Agent | str
    objective: str
    task_id: str | None = None
    expires_at: datetime | None = None


class RequestAccessBody(BaseModel):
    purpose: str
    items: list[AccessRequestItem]
    requested_ttl: timedelta = timedelta(minutes=15)
    max_uses: int | None = Field(default=None, ge=1)
    reason: str | None = None


class RequestStatus(BaseModel):
    request: AccessRequest
    decision: PolicyDecision
    grant: Grant | None = None


class RevealBody(BaseModel):
    resource: str
    task_id: str | None = None
    agent_id: str | None = None
    purpose: str | None = None


class ProveBody(BaseModel):
    claim: str
    task_id: str | None = None
    agent_id: str | None = None
    purpose: str | None = None


class UseBody(BaseModel):
    capability: str
    destination: str
    task_id: str | None = None
    agent_id: str | None = None
    purpose: str | None = None


def _default_authority() -> Authority:
    database = Path(
        os.environ.get("PAV_DB_PATH", Path.home() / ".local" / "share" / "pav" / "vault.sqlite3")
    ).expanduser()
    database.parent.mkdir(parents=True, exist_ok=True)
    return Authority(storage=SQLiteStorage(database))


def create_app(authority: Authority | None = None) -> FastAPI:
    authority = authority or _default_authority()
    api = FastAPI(title="Personal Authority Vault", version="0.1.0")

    @api.exception_handler(AuthorityError)
    async def authority_error_handler(_: Request, error: AuthorityError) -> JSONResponse:
        status = 403
        if isinstance(error, GrantInvalid):
            status = 410
        elif isinstance(error, ApprovalRequired):
            status = 409
        return JSONResponse(status_code=status, content={"detail": str(error)})

    def task_or_404(task_id: str) -> Task:
        task = authority.tasks.get(task_id)
        if task is None:
            raise HTTPException(status_code=404, detail=f"unknown task: {task_id}")
        return task

    def grant_or_404(grant_id: str) -> Grant:
        grant = authority.grants.get(grant_id)
        if grant is None:
            raise HTTPException(status_code=404, detail=f"unknown grant: {grant_id}")
        return grant

    def status_for(request_id: str) -> RequestStatus:
        request = authority.requests.get(request_id)
        decision = authority.decisions.get(request_id)
        if request is None or decision is None:
            raise HTTPException(status_code=404, detail=f"unknown access request: {request_id}")
        grant = next((grant for grant in authority.grants.values() if grant.request_id == request_id), None)
        return RequestStatus(request=request, decision=decision, grant=grant)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.post("/tasks", response_model=Task, status_code=201)
    def create_task(body: CreateTaskBody) -> Task:
        return authority.create_task(
            agent=body.agent,
            objective=body.objective,
            task_id=body.task_id,
            expires_at=body.expires_at,
        )

    @api.post("/tasks/{task_id}/access-requests", response_model=RequestStatus, status_code=201)
    def request_access(task_id: str, body: RequestAccessBody) -> RequestStatus:
        task = task_or_404(task_id)
        request = authority.request_access(
            task=task,
            purpose=body.purpose,
            items=body.items,
            requested_ttl=body.requested_ttl,
            max_uses=body.max_uses,
            reason=body.reason,
        )
        decision = authority.evaluate(request)
        grant = authority.authorize(decision) if decision.outcome is DecisionOutcome.ALLOW else None
        return RequestStatus(request=request, decision=decision, grant=grant)

    @api.get("/access-requests/{request_id}", response_model=RequestStatus)
    def get_request_status(request_id: str) -> RequestStatus:
        return status_for(request_id)

    @api.post("/access-requests/{request_id}/approve", response_model=RequestStatus, status_code=201)
    def approve_request(request_id: str) -> RequestStatus:
        current = status_for(request_id)
        if current.grant is not None:
            return current
        if current.decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
            raise HTTPException(status_code=409, detail="only approval-required requests can be approved")
        approved = authority.approve(current.decision)
        authority.authorize(approved)
        return status_for(request_id)

    @api.post("/grants/{grant_id}/reveal")
    def reveal(grant_id: str, body: RevealBody) -> dict[str, Any]:
        grant = grant_or_404(grant_id)
        return authority.reveal(
            grant=grant,
            resource=body.resource,
            task=body.task_id,
            agent=body.agent_id,
            purpose=body.purpose,
        )

    @api.post("/grants/{grant_id}/prove")
    def prove(grant_id: str, body: ProveBody) -> dict[str, Any]:
        grant = grant_or_404(grant_id)
        return authority.prove(
            grant=grant,
            claim=body.claim,
            task=body.task_id,
            agent=body.agent_id,
            purpose=body.purpose,
        )

    @api.post("/grants/{grant_id}/use")
    def use(grant_id: str, body: UseBody) -> dict[str, str]:
        grant = grant_or_404(grant_id)
        return authority.use(
            grant=grant,
            capability=body.capability,
            destination=body.destination,
            task=body.task_id,
            agent=body.agent_id,
            purpose=body.purpose,
        )

    @api.post("/grants/{grant_id}/revoke", response_model=Grant)
    def revoke(grant_id: str) -> Grant:
        grant = grant_or_404(grant_id)
        authority.revoke(grant=grant)
        return grant

    @api.get("/grants", response_model=list[Grant])
    def list_grants() -> list[Grant]:
        return list(authority.grants.values())

    @api.get("/grants/{grant_id}", response_model=Grant)
    def get_grant(grant_id: str) -> Grant:
        return grant_or_404(grant_id)

    @api.get("/audit")
    def audit(task_id: str | None = Query(default=None)) -> list[Any]:
        return authority.audit(task=task_id)

    return api


app = create_app()
