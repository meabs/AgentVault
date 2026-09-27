from enum import StrEnum


class AccessMode(StrEnum):
    REVEAL = "reveal"
    PROVE = "prove"
    USE = "use"


class Sensitivity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SECRET = "secret"


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class GrantState(StrEnum):
    REQUESTED = "requested"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    APPROVED = "approved"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"


class AuditEventType(StrEnum):
    TASK_CREATED = "TASK_CREATED"
    ACCESS_REQUESTED = "ACCESS_REQUESTED"
    POLICY_ALLOWED = "POLICY_ALLOWED"
    POLICY_DENIED = "POLICY_DENIED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_CODE_REJECTED = "APPROVAL_CODE_REJECTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    GRANT_ISSUED = "GRANT_ISSUED"
    ATTRIBUTE_REVEALED = "ATTRIBUTE_REVEALED"
    CLAIM_PROVED = "CLAIM_PROVED"
    CAPABILITY_USED = "CAPABILITY_USED"
    GRANT_REVOKED = "GRANT_REVOKED"
    GRANT_EXPIRED = "GRANT_EXPIRED"
