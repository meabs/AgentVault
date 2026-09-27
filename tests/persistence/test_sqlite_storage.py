from datetime import timedelta

from cryptography.fernet import Fernet

from pav.authority.service import Authority
from pav.domain.models import AccessRequestItem, Agent, Attribute, ExternalHandle, Policy
from pav.domain.types import AccessMode, DecisionOutcome, Sensitivity
from pav.persistence import SQLiteStorage


def test_sqlite_state_survives_a_fresh_authority_and_encrypts_attribute_values(tmp_path) -> None:
    database = tmp_path / "vault.sqlite3"
    key = Fernet.generate_key()
    attribute_value = "sensitive-value-that-must-not-be-in-sqlite"
    storage = SQLiteStorage(database, key=key)
    authority = Authority(
        storage=storage,
        attributes={
            "identity.email": Attribute(
                name="identity.email",
                value=attribute_value,
                sensitivity=Sensitivity.HIGH,
            )
        },
        external_handles={
            "credentials.booking_site": ExternalHandle(
                name="credentials.booking_site",
                uri="secret://mock/booking-site",
            )
        },
        policies=[
            Policy(
                name="email-access",
                purpose="test.*",
                mode=AccessMode.REVEAL,
                decision=DecisionOutcome.ALLOW,
                max_ttl=timedelta(minutes=5),
            )
        ],
    )
    task = authority.create_task(
        agent=Agent(id="test-agent", name="Persistence Test Agent"),
        objective="Verify durable state",
    )
    request = authority.request_access(
        task=task,
        purpose="test.persistence",
        items=[AccessRequestItem(mode=AccessMode.REVEAL, resource="identity.email")],
    )
    authority.authorize(authority.evaluate(request))

    fresh_storage = SQLiteStorage(database, key=key)
    fresh = Authority(storage=fresh_storage, policies=authority.policies)

    assert fresh.attributes["identity.email"].value == attribute_value
    assert "credentials.booking_site" in fresh.external_handles
    assert "test-agent" in fresh.agents
    assert task.id in fresh.tasks
    assert request.id in fresh.requests
    assert len(fresh.grants) == 1
    assert any(event.task_id == task.id for event in fresh.audit())
    assert attribute_value.encode() not in database.read_bytes()
