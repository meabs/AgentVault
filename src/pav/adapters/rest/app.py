from __future__ import annotations

import os
from html import escape
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from pav.authority.errors import AccessDenied, ApprovalRequired, AuthorityError, GrantInvalid
from pav.authority.service import Authority
from pav.adapters.notifications import Notifier, build_notifier
from pav.domain.models import AccessRequest, AccessRequestItem, Agent, Grant, PolicyDecision, Task
from pav.domain.types import AccessMode, AuditEventType, DecisionOutcome, GrantState
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
    approval_url: str | None = None


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


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _label(resource: str) -> str:
    words = resource.replace(".", " · ").replace("_", " ")
    return " ".join(word.capitalize() for word in words.split())


def _when(value: datetime) -> str:
    return value.astimezone().strftime("%d %b %Y, %H:%M %Z")


def _duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" + ("s" if hours != 1 else "")
    minutes = seconds // 60
    return f"{minutes} minute" + ("s" if minutes != 1 else "")


def _page(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_text(title)} · Personal Authority Vault</title>
  <style>
    :root {{
      color-scheme: light;
      --paper: #f5f2eb;
      --surface: #fffdf8;
      --ink: #202624;
      --muted: #66706b;
      --line: #d8d8ca;
      --accent: #c65d2e;
      --accent-dark: #8e371c;
      --teal: #176b65;
      --teal-wash: #e7f2ef;
      --amber-wash: #fff0d5;
      --red: #a43d35;
      --red-wash: #fbe9e5;
      --radius: 14px;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    a {{ color: var(--accent-dark); text-underline-offset: 3px; }}
    a:hover {{ color: var(--accent); }}
    :focus-visible {{ outline: 3px solid #e5a24b; outline-offset: 3px; }}
    header {{ border-bottom: 1px solid var(--line); background: rgba(255,253,248,.86); }}
    .nav, main {{ width: min(1120px, calc(100% - 40px)); margin: 0 auto; }}
    .nav {{ min-height: 76px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }}
    .brand {{ color: var(--ink); text-decoration: none; font-weight: 760; letter-spacing: -.03em; font-size: 1.12rem; }}
    .brand span {{ color: var(--accent); }}
    nav {{ display: flex; gap: 20px; flex-wrap: wrap; font-size: .92rem; }}
    nav a {{ color: var(--muted); text-decoration: none; }}
    nav a:hover {{ color: var(--ink); }}
    main {{ padding: 54px 0 80px; }}
    h1, h2, h3 {{ line-height: 1.08; letter-spacing: -.035em; margin: 0; }}
    h1 {{ font-size: clamp(2rem, 5vw, 3.7rem); max-width: 12ch; }}
    h2 {{ font-size: 1.45rem; }}
    h3 {{ font-size: 1rem; }}
    p {{ max-width: 72ch; }}
    .lede {{ color: var(--muted); max-width: 62ch; font-size: 1.05rem; margin: 18px 0 0; }}
    .topline {{ display: flex; align-items: end; justify-content: space-between; gap: 24px; margin-bottom: 34px; }}
    .topline p {{ margin: 0; color: var(--muted); }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; background: var(--line); border: 1px solid var(--line); margin: 42px 0 54px; }}
    .metric {{ background: var(--surface); padding: 22px; }}
    .metric dt {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .1em; font-weight: 700; }}
    .metric dd {{ margin: 3px 0 0; font-size: 2.25rem; font-weight: 760; letter-spacing: -.05em; }}
    .layout {{ display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(260px, .7fr); gap: 48px; align-items: start; }}
    .section-head {{ display: flex; justify-content: space-between; align-items: baseline; gap: 16px; border-bottom: 1px solid var(--line); padding-bottom: 12px; margin-bottom: 0; }}
    .section-head a {{ font-size: .9rem; }}
    .activity, .grant-list, .timeline {{ list-style: none; padding: 0; margin: 0; }}
    .activity li, .grant-list li, .timeline li {{ border-bottom: 1px solid var(--line); padding: 16px 0; }}
    .activity li:last-child, .grant-list li:last-child, .timeline li:last-child {{ border-bottom: 0; }}
    .activity time, .timeline time {{ display: block; color: var(--muted); font-size: .82rem; margin-top: 3px; }}
    .quiet {{ color: var(--muted); }}
    .notice {{ padding: 16px 18px; background: var(--amber-wash); border: 1px solid #e8c98d; border-radius: var(--radius); margin: 24px 0; }}
    .notice.success {{ background: var(--teal-wash); border-color: #b7d9d1; }}
    .notice.danger {{ background: var(--red-wash); border-color: #e5b5ad; }}
    .request-meta {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 0 30px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); margin: 34px 0; }}
    .request-meta div {{ padding: 15px 0; border-bottom: 1px solid var(--line); }}
    .request-meta div:nth-last-child(-n+2) {{ border-bottom: 0; }}
    .request-meta dt {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }}
    .request-meta dd {{ margin: 3px 0 0; }}
    .mode-section {{ margin-top: 34px; }}
    .mode-section header {{ background: transparent; border: 0; display: flex; align-items: baseline; justify-content: space-between; padding: 0 0 9px; border-bottom: 2px solid var(--ink); }}
    .mode-section header h2 {{ text-transform: uppercase; letter-spacing: .09em; font-size: .9rem; }}
    .mode-section header span {{ color: var(--muted); font-size: .86rem; }}
    .permission {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.5fr); gap: 18px; padding: 17px 0; border-bottom: 1px solid var(--line); }}
    .permission strong {{ font-weight: 700; }}
    .permission span {{ color: var(--muted); }}
    .actions {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 34px; align-items: end; }}
    .actions form {{ display: flex; gap: 10px; align-items: end; flex-wrap: wrap; }}
    .actions label {{ display: block; width: 100%; color: var(--muted); font-size: .85rem; font-weight: 700; }}
    .actions input {{ border: 1px solid var(--line); border-radius: 8px; padding: 11px 12px; font: inherit; letter-spacing: .08em; text-transform: uppercase; }}
    button, .button {{ border: 1px solid var(--accent-dark); background: var(--accent); color: white; border-radius: 8px; padding: 11px 18px; font: inherit; font-weight: 700; cursor: pointer; text-decoration: none; display: inline-block; }}
    button:hover, .button:hover {{ background: var(--accent-dark); color: white; }}
    button.secondary, .button.secondary {{ background: transparent; color: var(--accent-dark); }}
    button.secondary:hover, .button.secondary:hover {{ background: #f7e1d7; }}
    button.danger {{ background: var(--red); border-color: var(--red); }}
    .grant-row {{ display: flex; align-items: baseline; justify-content: space-between; gap: 18px; }}
    .grant-row p {{ margin: 3px 0 0; color: var(--muted); font-size: .92rem; }}
    .status {{ display: inline-block; color: var(--teal); font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }}
    .status.denied, .status.revoked {{ color: var(--red); }}
    .detail-list {{ margin: 26px 0; border-top: 1px solid var(--line); }}
    .detail-list div {{ display: grid; grid-template-columns: 170px 1fr; gap: 20px; padding: 13px 0; border-bottom: 1px solid var(--line); }}
    .detail-list dt {{ color: var(--muted); }}
    .detail-list dd {{ margin: 0; }}
    code {{ font: .9em ui-monospace, SFMono-Regular, Menlo, monospace; background: #ebe9df; padding: 2px 5px; border-radius: 4px; }}
    @media (max-width: 720px) {{
      .nav, main {{ width: min(100% - 28px, 620px); }}
      .nav {{ align-items: flex-start; flex-direction: column; padding: 18px 0; }}
      main {{ padding-top: 34px; }}
      .topline, .grant-row {{ display: block; }}
      .topline p {{ margin-top: 14px; }}
      .metrics, .layout {{ grid-template-columns: 1fr; }}
      .request-meta {{ grid-template-columns: 1fr; }}
      .request-meta div:nth-last-child(-n+2) {{ border-bottom: 1px solid var(--line); }}
      .request-meta div:last-child {{ border-bottom: 0; }}
      .permission, .detail-list div {{ grid-template-columns: 1fr; gap: 4px; }}
    }}
  </style>
</head>
<body>
  <header><div class="nav"><a class="brand" href="/">PAV<span>/</span> authority</a><nav aria-label="Primary"><a href="/">Overview</a><a href="/ui/grants">Grants</a><a href="/ui/tasks">Audit trails</a></nav></div></header>
  <main>{content}</main>
</body>
</html>"""


def _event_story(event: Any, authority: Authority) -> str:
    if event.event_type is AuditEventType.TASK_CREATED:
        return f"Task started — {_text(event.metadata.get('objective', 'new objective'))}"
    if event.event_type is AuditEventType.ACCESS_REQUESTED:
        resources = _text(event.metadata.get("resources", "requested context"))
        return f"Access requested for {_text(event.purpose or 'this task')} — {resources}"
    if event.event_type is AuditEventType.POLICY_ALLOWED:
        return f"Low-risk access allowed automatically — {_text(event.purpose or 'policy match')}"
    if event.event_type is AuditEventType.POLICY_DENIED:
        return f"Access denied by policy — {_text(event.purpose or 'protected request')}"
    if event.event_type is AuditEventType.APPROVAL_REQUESTED:
        return f"Human approval requested — {_text(event.purpose or 'additional authority')}"
    if event.event_type is AuditEventType.APPROVAL_CODE_REJECTED:
        return f"Approval code rejected — {_text(event.metadata.get('reason', 'invalid code'))}"
    if event.event_type is AuditEventType.APPROVAL_GRANTED:
        return f"Approval granted — {_text(event.purpose or 'request')}"
    if event.event_type is AuditEventType.APPROVAL_DENIED:
        return f"Approval denied — {_text(event.purpose or 'request')}"
    if event.event_type is AuditEventType.GRANT_ISSUED:
        return f"Task grant issued — {_text(event.purpose or 'bounded access')}"
    if event.event_type is AuditEventType.ATTRIBUTE_REVEALED:
        return f"{_text(_label(event.resource or 'Attribute'))} revealed"
    if event.event_type is AuditEventType.CLAIM_PROVED:
        if event.resource == "identity.age_over_18":
            return "Age-over-18 proved — date of birth NOT disclosed"
        return f"{_text(_label(event.resource or 'Claim'))} proved — source attribute NOT disclosed"
    if event.event_type is AuditEventType.CAPABILITY_USED:
        if event.resource == "credentials.booking_site":
            return "Booking credential used — credential NOT disclosed"
        return f"{_text(_label(event.resource or 'Capability'))} used — underlying secret NOT disclosed"
    if event.event_type is AuditEventType.GRANT_REVOKED:
        return "Grant revoked — future operations blocked"
    if event.event_type is AuditEventType.GRANT_EXPIRED:
        return "Grant expired — future operations blocked"
    return _text(event.event_type.value.replace("_", " ").title())


def _agent_name(authority: Authority, agent_id: str) -> str:
    agent = authority.agents.get(agent_id)
    return agent.name if agent else agent_id


def _default_authority() -> Authority:
    database = Path(
        os.environ.get("PAV_DB_PATH", Path.home() / ".local" / "share" / "pav" / "vault.sqlite3")
    ).expanduser()
    database.parent.mkdir(parents=True, exist_ok=True)
    return Authority(storage=SQLiteStorage(database))


def create_app(
    authority: Authority | None = None,
    *,
    notifier: Notifier | None = None,
    approval_base_url: str | None = None,
) -> FastAPI:
    authority = authority or _default_authority()
    notifier = notifier or build_notifier()
    approval_base_url = (approval_base_url or os.environ.get("PAV_APPROVAL_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
    api = FastAPI(title="Personal Authority Vault", version="0.1.0")
    api.state.notifier = notifier

    def approval_url(request_id: str) -> str:
        return f"{approval_base_url}/approvals/{request_id}"

    def prepare_approval(request_id: str) -> str:
        delivery = authority.create_approval_challenge(request_id)
        if delivery is not None:
            code, _ = delivery
            notifier.notify(request_id=request_id, code=code, approval_url=approval_url(request_id))
        return approval_url(request_id)

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
        return RequestStatus(
            request=request,
            decision=decision,
            grant=grant,
            approval_url=approval_url(request_id)
            if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
            else None,
        )

    def pending_requests() -> list[RequestStatus]:
        return sorted(
            (
                status_for(request_id)
                for request_id, decision in authority.decisions.items()
                if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
                and not decision.approved
                and request_id in authority.requests
            ),
            key=lambda status: status.request.created_at,
            reverse=True,
        )

    def approve_pending(request_id: str) -> RequestStatus:
        current = status_for(request_id)
        if current.grant is not None:
            return current
        if current.decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
            raise HTTPException(status_code=409, detail="only approval-required requests can be approved")
        approved = authority.approve(current.decision)
        authority.authorize(approved)
        return status_for(request_id)

    def deny_pending(request_id: str) -> RequestStatus:
        current = status_for(request_id)
        if current.grant is not None:
            raise HTTPException(status_code=409, detail="a granted request cannot be denied")
        if current.decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED:
            raise HTTPException(status_code=409, detail="only approval-required requests can be denied")
        authority.deny(current.decision)
        return status_for(request_id)

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/", response_class=HTMLResponse)
    def home() -> str:
        pending = pending_requests()
        active_grants = [grant for grant in authority.grants.values() if grant.state is GrantState.ACTIVE]
        events = authority.audit()[-8:][::-1]
        activity = "".join(
            f'<li><span>{_event_story(event, authority)}</span><time>{_text(_when(event.timestamp))}</time></li>'
            for event in events
        )
        if not activity:
            activity = '<li class="quiet">No activity yet. An MCP agent will appear here when it creates a task.</li>'
        pending_link = ", ".join(
            f'<a href="/approvals/{_text(status.request.id)}">{_text(_agent_name(authority, status.request.agent_id))}</a>'
            for status in pending[:3]
        )
        pending_note = (
            f'<p class="notice">Waiting for your decision: {pending_link}.</p>'
            if pending_link
            else '<p class="quiet">Nothing is waiting for approval.</p>'
        )
        content = f"""
        <div class="topline"><div><h1>Your authority, in view.</h1><p class="lede">A local boundary for what agents may know or do about you. Every grant is task-scoped, time-bound, and visible.</p></div></div>
        <dl class="metrics">
          <div class="metric"><dt>Pending requests</dt><dd>{len(pending)}</dd></div>
          <div class="metric"><dt>Active grants</dt><dd>{len(active_grants)}</dd></div>
          <div class="metric"><dt>Known agents</dt><dd>{len(authority.agents)}</dd></div>
        </dl>
        {pending_note}
        <div class="layout">
          <section><div class="section-head"><h2>Recent activity</h2><a href="/ui/tasks">View audit trails</a></div><ul class="activity">{activity}</ul></section>
          <aside><div class="section-head"><h2>Active grants</h2><a href="/ui/grants">View all</a></div><ul class="grant-list">{
            ''.join(
                f'<li><a href="/ui/grants/{_text(grant.id)}"><strong>{_text(_agent_name(authority, grant.agent_id))}</strong></a><p>{_text(grant.purpose)} · expires {_text(_when(grant.expires_at))}</p></li>'
                for grant in active_grants[:5]
            ) or '<li class="quiet">No active grants.</li>'
          }</ul></aside>
        </div>
        """
        return _page("Overview", content)

    @api.get("/approvals/{request_id}", response_class=HTMLResponse)
    def approval_screen(request_id: str) -> str:
        status = status_for(request_id)
        request = status.request
        decision = status.decision
        agent = authority.agents.get(request.agent_id)
        agent_display = agent.name if agent else request.agent_id
        destinations = sorted({item.destination for item in request.items if item.destination})
        destination_copy = ", ".join(_text(value) for value in destinations) or "No external destination specified"
        uses = decision.max_uses if decision.max_uses is not None else request.requested_max_uses
        uses_copy = f"{uses} use" + ("s" if uses != 1 else "") if uses is not None else "as needed within the grant"
        reason = request.reason or "Policy could not auto-authorize every requested item. Your approval is required."

        section_copy = {
            AccessMode.REVEAL: ("Values listed here will be shared with the requesting agent. Nothing else in your vault will be revealed.", "No reveal permissions requested."),
            AccessMode.PROVE: ("Only the derived result will be shared. The source attributes stay inside the vault.", "No proof permissions requested."),
            AccessMode.USE: ("PAV will exercise the capability at the approved destination. The underlying credential will not be shared with the agent.", "No use permissions requested."),
        }
        sections: list[str] = []
        for mode in (AccessMode.REVEAL, AccessMode.PROVE, AccessMode.USE):
            items = [item for item in request.items if item.mode is mode]
            rows = []
            for item in items:
                if mode is AccessMode.REVEAL:
                    detail = f"The {_text(_label(item.resource))} value will be disclosed. No other value will be disclosed."
                elif item.resource == "identity.age_over_18":
                    detail = "Only the yes/no age-over-18 result will be shared. Date of birth will not be shared."
                elif mode is AccessMode.PROVE:
                    detail = "Only the derived result will be shared. The source attribute will not be shared."
                else:
                    detail = f"PAV may use it at {_text(item.destination or 'the approved destination')}. The credential value will not be shared."
                rows.append(f'<div class="permission"><strong>{_text(_label(item.resource))}</strong><span>{detail}</span></div>')
            body = "".join(rows) or f'<p class="quiet">{section_copy[mode][1]}</p>'
            sections.append(f'<section class="mode-section"><header><h2>{_text(mode.value.upper())}</h2><span>{section_copy[mode][0]}</span></header>{body}</section>')

        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED and not decision.approved and status.grant is None:
            banner = '<div class="notice">This request is waiting for your decision. A human-presence code was sent to your desktop notification. It is not shown on this page. Enter it to approve; denying never requires the code.</div>'
            actions = f'<div class="actions"><form method="post" action="/approvals/{_text(request.id)}/approve"><label for="approval-code">Human-presence code</label><input id="approval-code" name="code" type="text" inputmode="text" autocomplete="off" required><button type="submit">Approve request</button></form><form method="post" action="/approvals/{_text(request.id)}/deny"><button class="secondary" type="submit">Deny request</button></form></div>'
        elif status.grant is not None:
            banner = f'<div class="notice success"><strong>Approved.</strong> Grant <a href="/ui/grants/{_text(status.grant.id)}">{_text(status.grant.id)}</a> is active until {_text(_when(status.grant.expires_at))}.</div>'
            actions = '<div class="actions"><a class="button secondary" href="/">Return home</a></div>'
        else:
            banner = '<div class="notice danger"><strong>Denied.</strong> No grant was issued. The agent must request authority again if the task changes.</div>'
            actions = '<div class="actions"><a class="button secondary" href="/">Return home</a></div>'

        content = f"""
        <div class="topline"><div><h1>Review this request.</h1><p class="lede">Make a deliberate decision about one agent, one task, and one bounded purpose.</p></div><span class="status">{_text(decision.outcome.value.replace('_', ' '))}</span></div>
        {banner}
        <dl class="request-meta">
          <div><dt>Who is asking?</dt><dd><strong>{_text(agent_display)}</strong>{f' · {_text(agent.runtime)}' if agent and agent.runtime else ''}</dd></div>
          <div><dt>What do they want?</dt><dd>{_text(request.purpose)}<br><span class="quiet">{_text(request.id)}</span></dd></div>
          <div><dt>Why do they want it?</dt><dd>{_text(reason)}<br><span class="quiet">Task: {_text(request.task_id)} — {_text(authority.tasks.get(request.task_id).objective if request.task_id in authority.tasks else 'unknown objective')}</span></dd></div>
          <div><dt>Where will it be used?</dt><dd>{destination_copy}<br><span class="quiet">Returned to {_text(agent_display)} through the MCP connection.</span></dd></div>
          <div><dt>For how long?</dt><dd>{_text(_duration(request.requested_ttl))} from approval · {uses_copy}</dd></div>
        </dl>
        {''.join(sections)}
        {actions}
        """
        return _page("Review request", content)

    @api.post("/approvals/{request_id}/approve")
    def ui_approve_request(request_id: str, code: str | None = Form(default=None)) -> RedirectResponse:
        failure = authority.consume_approval_code(request_id, code)
        if failure is not None:
            authority.record_approval_code_failure(request_id, failure)
            messages = {
                "missing": "approval code is required",
                "incorrect": "approval code is incorrect",
                "expired": "approval code has expired",
                "already_used": "approval code was already used",
                "unavailable": "approval code is unavailable",
            }
            raise HTTPException(status_code=403, detail=messages[failure])
        approve_pending(request_id)
        return RedirectResponse(url=f"/approvals/{request_id}", status_code=303)

    @api.post("/approvals/{request_id}/deny")
    def ui_deny_request(request_id: str) -> RedirectResponse:
        deny_pending(request_id)
        return RedirectResponse(url=f"/approvals/{request_id}", status_code=303)

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
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
            prepare_approval(request.id)
        return RequestStatus(
            request=request,
            decision=decision,
            grant=grant,
            approval_url=approval_url(request.id)
            if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED
            else None,
        )

    @api.get("/access-requests/{request_id}", response_model=RequestStatus)
    def get_request_status(request_id: str) -> RequestStatus:
        return status_for(request_id)

    @api.post("/access-requests/{request_id}/deny", response_model=RequestStatus, status_code=201)
    def deny_request(request_id: str) -> RequestStatus:
        return deny_pending(request_id)

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

    @api.get("/ui/grants", response_class=HTMLResponse)
    def grants_page() -> str:
        grants = sorted(authority.grants.values(), key=lambda grant: grant.issued_at, reverse=True)
        active = [grant for grant in grants if grant.state is GrantState.ACTIVE]
        historical = [grant for grant in grants if grant.state is not GrantState.ACTIVE]

        def rows(values: list[Grant]) -> str:
            return "".join(
                f'<li><div class="grant-row"><div><a href="/ui/grants/{_text(grant.id)}"><strong>{_text(_agent_name(authority, grant.agent_id))}</strong></a><p>{_text(grant.purpose)} · task {_text(grant.task_id)}</p></div><span class="status {_text(grant.state.value)}">{_text(grant.state.value)}</span></div></li>'
                for grant in values
            ) or '<li class="quiet">None.</li>'

        content = f"""
        <div class="topline"><div><h1>Task grants.</h1><p class="lede">Every permission below is bound to an agent, a task, a purpose, and an expiry.</p></div></div>
        <div class="layout"><section><div class="section-head"><h2>Active now</h2><span>{len(active)} grants</span></div><ul class="grant-list">{rows(active)}</ul></section><aside><div class="section-head"><h2>History</h2><span>{len(historical)} grants</span></div><ul class="grant-list">{rows(historical)}</ul></aside></div>
        """
        return _page("Task grants", content)

    @api.get("/ui/grants/{grant_id}", response_class=HTMLResponse)
    def grant_detail(grant_id: str) -> str:
        grant = grant_or_404(grant_id)
        permissions = "".join(
            f'<li><strong>{_text(permission.mode.value.upper())}</strong> · {_text(_label(permission.resource))}{f" · {_text(permission.destination)}" if permission.destination else ""}</li>'
            for permission in grant.permissions
        )
        events = [event for event in authority.audit(task=grant.task_id) if event.grant_id == grant.id]
        timeline = "".join(
            f'<li><span>{_event_story(event, authority)}</span><time>{_text(_when(event.timestamp))}</time></li>'
            for event in reversed(events)
        ) or '<li class="quiet">No operations recorded for this grant yet.</li>'
        revoke = (
            f'<form method="post" action="/ui/grants/{_text(grant.id)}/revoke"><button class="danger" type="submit">Revoke grant</button></form>'
            if grant.state is GrantState.ACTIVE else ""
        )
        content = f"""
        <div class="topline"><div><h1>Grant detail.</h1><p class="lede">Inspect exactly what this task can do, and stop it from being used again.</p></div><span class="status {_text(grant.state.value)}">{_text(grant.state.value)}</span></div>
        <dl class="detail-list">
          <div><dt>Agent</dt><dd>{_text(_agent_name(authority, grant.agent_id))} <span class="quiet">({_text(grant.agent_id)})</span></dd></div>
          <div><dt>Purpose</dt><dd>{_text(grant.purpose)}</dd></div>
          <div><dt>Task</dt><dd><a href="/ui/tasks/{_text(grant.task_id)}/audit">{_text(grant.task_id)}</a></dd></div>
          <div><dt>Issued</dt><dd>{_text(_when(grant.issued_at))}</dd></div>
          <div><dt>Expires</dt><dd>{_text(_when(grant.expires_at))}</dd></div>
          <div><dt>Use count</dt><dd>{grant.uses}{f' / {grant.max_uses}' if grant.max_uses is not None else ' / unlimited for this grant'}</dd></div>
          <div><dt>Permissions</dt><dd><ul>{permissions}</ul></dd></div>
        </dl>
        <div class="actions">{revoke}<a class="button secondary" href="/ui/tasks/{_text(grant.task_id)}/audit">View task audit</a></div>
        <section style="margin-top: 54px"><div class="section-head"><h2>Grant timeline</h2></div><ul class="timeline">{timeline}</ul></section>
        <p class="quiet" style="margin-top: 28px">Revoking stops future use. Values already revealed to an external agent cannot be recalled.</p>
        """
        return _page("Grant detail", content)

    @api.post("/ui/grants/{grant_id}/revoke")
    def ui_revoke_grant(grant_id: str) -> RedirectResponse:
        grant = grant_or_404(grant_id)
        authority.revoke(grant=grant)
        return RedirectResponse(url=f"/ui/grants/{grant_id}", status_code=303)

    @api.get("/ui/tasks", response_class=HTMLResponse)
    def task_audits() -> str:
        tasks = sorted(authority.tasks.values(), key=lambda task: task.created_at, reverse=True)
        rows = "".join(
            f'<li><a href="/ui/tasks/{_text(task.id)}/audit"><strong>{_text(task.objective)}</strong></a><p>{_text(_agent_name(authority, task.agent_id))} · {_text(task.id)}</p></li>'
            for task in tasks
        ) or '<li class="quiet">No task activity yet.</li>'
        content = f'<div class="topline"><div><h1>Audit trails.</h1><p class="lede">A plain-language record of what each task asked for, what was approved, and what was actually used.</p></div></div><ul class="grant-list">{rows}</ul>'
        return _page("Audit trails", content)

    @api.get("/ui/tasks/{task_id}/audit", response_class=HTMLResponse)
    def task_audit(task_id: str) -> str:
        task = task_or_404(task_id)
        events = authority.audit(task=task)
        timeline = "".join(
            f'<li><span>{_event_story(event, authority)}</span><time>{_text(_when(event.timestamp))}</time></li>'
            for event in reversed(events)
        ) or '<li class="quiet">No events for this task.</li>'
        content = f"""
        <div class="topline"><div><h1>Task story.</h1><p class="lede">{_text(task.objective)}</p></div></div>
        <dl class="detail-list"><div><dt>Task</dt><dd>{_text(task.id)}</dd></div><div><dt>Agent</dt><dd>{_text(_agent_name(authority, task.agent_id))}</dd></div><div><dt>Started</dt><dd>{_text(_when(task.created_at))}</dd></div></dl>
        <ul class="timeline">{timeline}</ul>
        """
        return _page("Task audit", content)

    @api.get("/grants/{grant_id}", response_model=Grant)
    def get_grant(grant_id: str) -> Grant:
        return grant_or_404(grant_id)

    @api.get("/audit")
    def audit(task_id: str | None = Query(default=None)) -> list[Any]:
        return authority.audit(task=task_id)

    return api


app = create_app()
