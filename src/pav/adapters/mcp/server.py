from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from pav.authority.errors import AuthorityError
from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent, Grant, PolicyDecision, Task
from pav.domain.types import DecisionOutcome
from pav.persistence import SQLiteStorage


@contextmanager
def _translate_expected_errors():
    try:
        yield
    except (AuthorityError, ValueError) as error:
        raise ToolError(str(error)) from error


def _default_authority() -> Authority:
    database = Path(
        os.environ.get("PAV_DB_PATH", Path.home() / ".local" / "share" / "pav" / "vault.sqlite3")
    ).expanduser()
    database.parent.mkdir(parents=True, exist_ok=True)
    return Authority(storage=SQLiteStorage(database))


def _json_model(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _grant_metadata(grant: Grant) -> dict[str, Any]:
    """Return grant metadata without any attribute or secret values."""
    return {
        "id": grant.id,
        "agent_id": grant.agent_id,
        "task_id": grant.task_id,
        "purpose": grant.purpose,
        "request_id": grant.request_id,
        "state": grant.state.value,
        "issued_at": grant.issued_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "max_uses": grant.max_uses,
        "uses": grant.uses,
        "permissions": [
            {
                "mode": permission.mode.value,
                "resource": permission.resource,
                "destination": permission.destination,
            }
            for permission in grant.permissions
        ],
    }


def _task_or_error(authority: Authority, task_id: str) -> Task:
    task = authority.tasks.get(task_id)
    if task is None:
        raise ValueError(f"unknown task: {task_id}")
    return task


def _grant_or_error(authority: Authority, grant_id: str) -> Grant:
    grant = authority.grants.get(grant_id)
    if grant is None:
        raise ValueError(f"unknown grant: {grant_id}")
    return grant


def _status_for(authority: Authority, request_id: str) -> dict[str, Any]:
    request = authority.requests.get(request_id)
    decision = authority.decisions.get(request_id)
    if request is None or decision is None:
        raise ValueError(f"unknown access request: {request_id}")
    grant = next(
        (candidate for candidate in authority.grants.values() if candidate.request_id == request_id),
        None,
    )
    return _request_result(request_id, request, decision, grant)


def _request_result(
    request_id: str,
    request: Any,
    decision: PolicyDecision,
    grant: Grant | None,
) -> dict[str, Any]:
    if grant is not None:
        status = "granted"
    elif decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
        status = "approval_required"
    elif decision.outcome is DecisionOutcome.DENY:
        status = "denied"
    else:
        status = "pending"
    return {
        "status": status,
        "request_id": request_id,
        "request": _json_model(request),
        "decision": _json_model(decision),
        "grant": _grant_metadata(grant) if grant is not None else None,
    }


def create_server(authority: Authority | None = None) -> MCPServer:
    """Create an MCP server whose tools delegate to one Authority instance."""
    authority = authority or _default_authority()
    server = MCPServer(
        "Personal Authority Vault",
        version="0.1.0",
        instructions=(
            "PAV is a task-scoped authority broker. Discover metadata first, request only "
            "the minimum access required, and use the returned grant for protected operations."
        ),
    )

    @server.tool(
        name="vault.list_available_context",
        description=(
            "List available attribute, claim, and capability names with safe metadata only. "
            "This tool never returns underlying values."
        ),
        structured_output=True,
    )
    def list_available_context() -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for name, attribute in sorted(authority.attributes.items()):
            items.append(
                {
                    "name": name,
                    "kind": "attribute",
                    "description": "Personal attribute available through an authorized reveal operation.",
                    "sensitivity": attribute.sensitivity.value,
                    "access_modes": ["reveal"],
                }
            )
        for name in sorted(authority.claims):
            items.append(
                {
                    "name": name,
                    "kind": "claim",
                    "description": "Derived claim available through an authorized prove operation.",
                    "sensitivity": "medium",
                    "access_modes": ["prove"],
                }
            )
        for name, handle in sorted(authority.external_handles.items()):
            items.append(
                {
                    "name": name,
                    "kind": "capability",
                    "description": "External capability available through an authorized use operation.",
                    "sensitivity": handle.sensitivity.value,
                    "access_modes": ["use"],
                }
            )
        return {"items": items}

    @server.tool(
        name="vault.request_access",
        description=(
            "Create a task when task_id is omitted, request exact reveal/prove/use permissions, "
            "and evaluate the request. Returns a grant, approval_required status, or denial."
        ),
        structured_output=True,
    )
    def request_access(
        purpose: str,
        items: list[AccessRequestItem],
        agent_id: str | None = None,
        agent_name: str | None = None,
        objective: str | None = None,
        task_id: str | None = None,
        requested_ttl_seconds: Annotated[int, Field(ge=1)] = 900,
        max_uses: Annotated[int | None, Field(ge=1)] = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        with _translate_expected_errors():
            if task_id is None:
                if not agent_id:
                    raise ValueError("agent_id is required when task_id is omitted")
                if not objective:
                    raise ValueError("objective is required when task_id is omitted")
                task = authority.create_task(
                    agent=Agent(id=agent_id, name=agent_name or agent_id, protocol="mcp"),
                    objective=objective,
                )
            else:
                task = _task_or_error(authority, task_id)
                if agent_id is not None and agent_id != task.agent_id:
                    raise ValueError("task is bound to a different agent")

            request = authority.request_access(
                task=task,
                purpose=purpose,
                items=items,
                requested_ttl=timedelta(seconds=requested_ttl_seconds),
                max_uses=max_uses,
                reason=reason,
            )
            decision = authority.evaluate(request)
            grant = authority.authorize(decision) if decision.outcome is DecisionOutcome.ALLOW else None
            result = _request_result(request.id, request, decision, grant)
            result["task"] = _json_model(task)
            return result

    @server.tool(
        name="vault.get_request_status",
        description="Return an access request's decision and any issued grant, without protected values.",
        structured_output=True,
    )
    def get_request_status(request_id: str) -> dict[str, Any]:
        with _translate_expected_errors():
            return _status_for(authority, request_id)

    @server.tool(
        name="vault.approve_request",
        description=(
            "Temporary Phase 1 approval stand-in: approve an approval-required request and issue its grant."
        ),
        structured_output=True,
    )
    def approve_request(request_id: str) -> dict[str, Any]:
        with _translate_expected_errors():
            current = _status_for(authority, request_id)
            if current["grant"] is not None:
                return current
            decision = authority.decisions[request_id]
            if decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
                raise ValueError("only approval-required requests can be approved")
            approved = authority.approve(decision)
            grant = authority.authorize(approved)
            return _status_for(authority, grant.request_id or request_id)

    @server.tool(
        name="vault.reveal",
        description="Reveal one attribute value allowed by a grant after grant enforcement.",
        structured_output=True,
    )
    def reveal(
        grant_id: str,
        resource: str,
        task_id: str | None = None,
        agent_id: str | None = None,
        purpose: str | None = None,
    ) -> dict[str, Any]:
        with _translate_expected_errors():
            return authority.reveal(
                grant=_grant_or_error(authority, grant_id),
                resource=resource,
                task=task_id,
                agent=agent_id,
                purpose=purpose,
            )

    @server.tool(
        name="vault.prove",
        description="Return a derived claim result allowed by a grant without returning source attributes.",
        structured_output=True,
    )
    def prove(
        grant_id: str,
        claim: str,
        task_id: str | None = None,
        agent_id: str | None = None,
        purpose: str | None = None,
    ) -> dict[str, Any]:
        with _translate_expected_errors():
            return authority.prove(
                grant=_grant_or_error(authority, grant_id),
                claim=claim,
                task=task_id,
                agent=agent_id,
                purpose=purpose,
            )

    @server.tool(
        name="vault.use",
        description="Exercise an approved external capability without returning its underlying secret.",
        structured_output=True,
    )
    def use(
        grant_id: str,
        capability: str,
        destination: str,
        task_id: str | None = None,
        agent_id: str | None = None,
        purpose: str | None = None,
    ) -> dict[str, str]:
        with _translate_expected_errors():
            return authority.use(
                grant=_grant_or_error(authority, grant_id),
                capability=capability,
                destination=destination,
                task=task_id,
                agent=agent_id,
                purpose=purpose,
            )

    @server.tool(
        name="vault.get_grant",
        description="Return grant metadata and permissions, never underlying attribute or secret values.",
        structured_output=True,
    )
    def get_grant(grant_id: str) -> dict[str, Any]:
        with _translate_expected_errors():
            return _grant_metadata(_grant_or_error(authority, grant_id))

    @server.tool(
        name="vault.revoke_grant",
        description="Revoke a grant so future protected operations fail, then return its metadata.",
        structured_output=True,
    )
    def revoke_grant(grant_id: str) -> dict[str, Any]:
        with _translate_expected_errors():
            grant = _grant_or_error(authority, grant_id)
            authority.revoke(grant=grant)
            return _grant_metadata(grant)

    return server


mcp = create_server()


if __name__ == "__main__":
    mcp.run(transport=os.environ.get("PAV_MCP_TRANSPORT", "stdio"))
