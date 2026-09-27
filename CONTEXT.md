# PAV Domain Context

- **Attribute**: a named, typed personal fact or preference with sensitivity metadata.
- **Derived claim**: a deterministic assertion calculated from one or more attributes; its response does not disclose its source attributes.
- **External handle**: an opaque reference to sensitive material owned by another provider; Phase 0 can exercise it but does not reveal its value.
- **Agent**: a registered software actor that requests authority.
- **Task**: the bounded unit of user intent to which requests and grants are bound.
- **Purpose**: the machine-readable reason for a request, separate from agent identity.
- **Access request**: a task-scoped proposal containing exact reveal, prove, or use items.
- **Grant**: a time- and scope-bounded delegation issued after policy allowance or explicit approval.
- **Grant permission**: one mode/resource/destination tuple allowed by a grant.
- **Policy**: a deterministic rule that returns allow, deny, or approval-required for a request item.
- **Audit event**: metadata describing an authority decision or protected operation without copying sensitive values.
