from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Mapping
from datetime import date, datetime
from pathlib import Path
from threading import RLock
from typing import Protocol

from cryptography.fernet import Fernet

from pav.domain.models import (
    AccessRequest,
    ApprovalChallenge,
    Agent,
    Attribute,
    AuditEvent,
    ClaimDefinition,
    ExternalHandle,
    Grant,
    PolicyDecision,
    Task,
)


class AuthorityStorage(Protocol):
    """Small persistence seam used by Authority."""

    def load_attributes(self) -> dict[str, Attribute]: ...
    def save_attribute(self, attribute: Attribute) -> None: ...
    def load_claims(
        self, evaluators: Mapping[str, Callable] | None = None
    ) -> dict[str, ClaimDefinition]: ...
    def save_claim(self, claim: ClaimDefinition) -> None: ...
    def load_external_handles(self) -> dict[str, ExternalHandle]: ...
    def save_external_handle(self, handle: ExternalHandle) -> None: ...
    def load_agents(self) -> dict[str, Agent]: ...
    def save_agent(self, agent: Agent) -> None: ...
    def load_tasks(self) -> dict[str, Task]: ...
    def save_task(self, task: Task) -> None: ...
    def load_requests(self) -> dict[str, AccessRequest]: ...
    def save_request(self, request: AccessRequest) -> None: ...
    def load_decisions(self) -> dict[str, PolicyDecision]: ...
    def save_decision(self, decision: PolicyDecision) -> None: ...
    def load_approval_challenges(self) -> dict[str, ApprovalChallenge]: ...
    def save_approval_challenge(self, challenge: ApprovalChallenge) -> None: ...
    def load_grants(self) -> dict[str, Grant]: ...
    def save_grant(self, grant: Grant) -> None: ...
    def load_audit_events(self) -> list[AuditEvent]: ...
    def append_audit_event(self, event: AuditEvent) -> None: ...


def _encode_value(value: object) -> object:
    if isinstance(value, datetime):
        return {"__pav_type__": "datetime", "value": value.isoformat()}
    if isinstance(value, date):
        return {"__pav_type__": "date", "value": value.isoformat()}
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    if isinstance(value, tuple):
        return {"__pav_type__": "tuple", "value": [_encode_value(item) for item in value]}
    if isinstance(value, dict):
        return {str(key): _encode_value(item) for key, item in value.items()}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"unsupported attribute value type: {type(value).__name__}")


def _decode_value(value: object) -> object:
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    if isinstance(value, dict):
        marker = value.get("__pav_type__")
        if marker == "date":
            return date.fromisoformat(str(value["value"]))
        if marker == "datetime":
            return datetime.fromisoformat(str(value["value"]))
        if marker == "tuple":
            return tuple(_decode_value(item) for item in value["value"])
        return {key: _decode_value(item) for key, item in value.items()}
    return value


def _json_value(value: object) -> str:
    return json.dumps(_encode_value(value), separators=(",", ":"), sort_keys=True)


class InMemoryStorage:
    """Phase 0-compatible storage adapter."""

    def __init__(self) -> None:
        self.attributes: dict[str, Attribute] = {}
        self.claims: dict[str, ClaimDefinition] = {}
        self.external_handles: dict[str, ExternalHandle] = {}
        self.agents: dict[str, Agent] = {}
        self.tasks: dict[str, Task] = {}
        self.requests: dict[str, AccessRequest] = {}
        self.decisions: dict[str, PolicyDecision] = {}
        self.approval_challenges: dict[str, ApprovalChallenge] = {}
        self.grants: dict[str, Grant] = {}
        self.audit_events: list[AuditEvent] = []

    def load_attributes(self) -> dict[str, Attribute]:
        return dict(self.attributes)

    def save_attribute(self, attribute: Attribute) -> None:
        self.attributes[attribute.name] = attribute

    def load_claims(self, evaluators: Mapping[str, Callable] | None = None) -> dict[str, ClaimDefinition]:
        return {
            name: claim.model_copy(update={"evaluator": evaluators.get(name, claim.evaluator)})
            for name, claim in self.claims.items()
        } if evaluators else dict(self.claims)

    def save_claim(self, claim: ClaimDefinition) -> None:
        self.claims[claim.name] = claim

    def load_external_handles(self) -> dict[str, ExternalHandle]:
        return dict(self.external_handles)

    def save_external_handle(self, handle: ExternalHandle) -> None:
        self.external_handles[handle.name] = handle

    def load_agents(self) -> dict[str, Agent]:
        return dict(self.agents)

    def save_agent(self, agent: Agent) -> None:
        self.agents[agent.id] = agent

    def load_tasks(self) -> dict[str, Task]:
        return dict(self.tasks)

    def save_task(self, task: Task) -> None:
        self.tasks[task.id] = task

    def load_requests(self) -> dict[str, AccessRequest]:
        return dict(self.requests)

    def save_request(self, request: AccessRequest) -> None:
        self.requests[request.id] = request

    def load_decisions(self) -> dict[str, PolicyDecision]:
        return dict(self.decisions)

    def save_decision(self, decision: PolicyDecision) -> None:
        self.decisions[decision.request.id] = decision

    def load_approval_challenges(self) -> dict[str, ApprovalChallenge]:
        return dict(self.approval_challenges)

    def save_approval_challenge(self, challenge: ApprovalChallenge) -> None:
        self.approval_challenges[challenge.request_id] = challenge

    def load_grants(self) -> dict[str, Grant]:
        return dict(self.grants)

    def save_grant(self, grant: Grant) -> None:
        self.grants[grant.id] = grant

    def load_audit_events(self) -> list[AuditEvent]:
        return list(self.audit_events)

    def append_audit_event(self, event: AuditEvent) -> None:
        self.audit_events.append(event)


class SQLiteStorage:
    """SQLite adapter with application-level Fernet encryption for attributes."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes | str | None = None,
        key_file: str | Path | None = None,
    ) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._fernet = Fernet(self._resolve_key(key, key_file))
        self._create_schema()

    def _resolve_key(self, key: bytes | str | None, key_file: str | Path | None) -> bytes:
        if key is not None:
            return key.encode() if isinstance(key, str) else key
        environment_key = os.environ.get("PAV_ENCRYPTION_KEY")
        if environment_key:
            return environment_key.encode()
        resolved_key_file = Path(
            key_file or os.environ.get("PAV_KEY_FILE", f"{self.path}.key")
        ).expanduser()
        resolved_key_file.parent.mkdir(parents=True, exist_ok=True)
        if resolved_key_file.exists():
            return resolved_key_file.read_bytes().strip()
        generated = Fernet.generate_key()
        resolved_key_file.write_bytes(generated)
        os.chmod(resolved_key_file, 0o600)
        return generated

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS attributes (
                    name TEXT PRIMARY KEY,
                    value_encrypted BLOB NOT NULL,
                    sensitivity TEXT NOT NULL,
                    schema_type TEXT,
                    provenance TEXT,
                    verified INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS claims (
                    name TEXT PRIMARY KEY,
                    source_attributes TEXT NOT NULL,
                    evaluator_ref TEXT
                );
                CREATE TABLE IF NOT EXISTS external_handles (
                    name TEXT PRIMARY KEY,
                    uri TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'mock',
                    allowed_destinations TEXT NOT NULL DEFAULT '[]',
                    sensitivity TEXT NOT NULL,
                    resource_type TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS approval_challenges (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    sequence INTEGER UNIQUE NOT NULL
                );
                """
            )
            columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(external_handles)")
            }
            if "provider" not in columns:
                self._connection.execute(
                    "ALTER TABLE external_handles ADD COLUMN provider TEXT NOT NULL DEFAULT 'mock'"
                )
            if "allowed_destinations" not in columns:
                self._connection.execute(
                    "ALTER TABLE external_handles ADD COLUMN allowed_destinations TEXT NOT NULL DEFAULT '[]'"
                )

    def _execute(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        with self._lock, self._connection:
            return list(self._connection.execute(sql, parameters))

    def load_attributes(self) -> dict[str, Attribute]:
        rows = self._execute("SELECT * FROM attributes")
        return {
            row["name"]: Attribute(
                name=row["name"],
                value=_decode_value(json.loads(self._fernet.decrypt(row["value_encrypted"]))),
                sensitivity=row["sensitivity"],
                schema_type=row["schema_type"],
                provenance=row["provenance"],
                verified=bool(row["verified"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        }

    def save_attribute(self, attribute: Attribute) -> None:
        encrypted = self._fernet.encrypt(_json_value(attribute.value).encode())
        self._execute(
            """INSERT OR REPLACE INTO attributes
            (name, value_encrypted, sensitivity, schema_type, provenance, verified, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                attribute.name,
                encrypted,
                attribute.sensitivity.value,
                attribute.schema_type,
                attribute.provenance,
                int(attribute.verified),
                attribute.created_at.isoformat(),
                attribute.updated_at.isoformat(),
            ),
        )

    def load_claims(self, evaluators: Mapping[str, Callable] | None = None) -> dict[str, ClaimDefinition]:
        rows = self._execute("SELECT * FROM claims")
        return {
            row["name"]: ClaimDefinition(
                name=row["name"],
                source_attributes=json.loads(row["source_attributes"]),
                evaluator=(evaluators or {}).get(row["name"]),
            )
            for row in rows
        }

    def save_claim(self, claim: ClaimDefinition) -> None:
        evaluator = claim.evaluator
        evaluator_ref = None if evaluator is None else f"{evaluator.__module__}:{evaluator.__qualname__}"
        self._execute(
            "INSERT OR REPLACE INTO claims (name, source_attributes, evaluator_ref) VALUES (?, ?, ?)",
            (claim.name, json.dumps(claim.source_attributes), evaluator_ref),
        )

    def load_external_handles(self) -> dict[str, ExternalHandle]:
        return {
            row["name"]: ExternalHandle(
                name=row["name"],
                uri=row["uri"],
                provider=row["provider"],
                allowed_destinations=set(json.loads(row["allowed_destinations"])),
                sensitivity=row["sensitivity"],
                resource_type=row["resource_type"],
            )
            for row in self._execute("SELECT * FROM external_handles")
        }

    def save_external_handle(self, handle: ExternalHandle) -> None:
        self._execute(
            """INSERT OR REPLACE INTO external_handles
            (name, uri, provider, allowed_destinations, sensitivity, resource_type)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                handle.name,
                handle.uri,
                handle.provider,
                json.dumps(sorted(handle.allowed_destinations)),
                handle.sensitivity.value,
                handle.resource_type,
            ),
        )

    def _load_models(self, table: str, model_type: type) -> dict[str, object]:
        return {
            row["id"]: model_type.model_validate_json(row["payload"])
            for row in self._execute(f"SELECT id, payload FROM {table}")
        }

    def _save_model(self, table: str, identifier: str, model: object) -> None:
        self._execute(
            f"INSERT OR REPLACE INTO {table} (id, payload) VALUES (?, ?)",
            (identifier, model.model_dump_json()),
        )

    def load_agents(self) -> dict[str, Agent]:
        return self._load_models("agents", Agent)

    def save_agent(self, agent: Agent) -> None:
        self._save_model("agents", agent.id, agent)

    def load_tasks(self) -> dict[str, Task]:
        return self._load_models("tasks", Task)

    def save_task(self, task: Task) -> None:
        self._save_model("tasks", task.id, task)

    def load_requests(self) -> dict[str, AccessRequest]:
        return self._load_models("requests", AccessRequest)

    def save_request(self, request: AccessRequest) -> None:
        self._save_model("requests", request.id, request)

    def load_decisions(self) -> dict[str, PolicyDecision]:
        return {
            row["request_id"]: PolicyDecision.model_validate_json(row["payload"])
            for row in self._execute("SELECT request_id, payload FROM decisions")
        }

    def save_decision(self, decision: PolicyDecision) -> None:
        self._execute(
            "INSERT OR REPLACE INTO decisions (request_id, payload) VALUES (?, ?)",
            (decision.request.id, decision.model_dump_json()),
        )

    def load_approval_challenges(self) -> dict[str, ApprovalChallenge]:
        return {
            row["request_id"]: ApprovalChallenge.model_validate_json(row["payload"])
            for row in self._execute("SELECT request_id, payload FROM approval_challenges")
        }

    def save_approval_challenge(self, challenge: ApprovalChallenge) -> None:
        self._execute(
            "INSERT OR REPLACE INTO approval_challenges (request_id, payload) VALUES (?, ?)",
            (challenge.request_id, challenge.model_dump_json()),
        )

    def load_grants(self) -> dict[str, Grant]:
        return self._load_models("grants", Grant)

    def save_grant(self, grant: Grant) -> None:
        self._save_model("grants", grant.id, grant)

    def load_audit_events(self) -> list[AuditEvent]:
        return [
            AuditEvent.model_validate_json(row["payload"])
            for row in self._execute("SELECT payload FROM audit_events ORDER BY sequence")
        ]

    def append_audit_event(self, event: AuditEvent) -> None:
        self._execute(
            "INSERT INTO audit_events (id, payload, sequence) VALUES (?, ?, COALESCE((SELECT MAX(sequence) + 1 FROM audit_events), 1))",
            (event.id, event.model_dump_json()),
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()
