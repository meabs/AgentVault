class AuthorityError(Exception):
    """Base error for denied or invalid authority operations."""


class AccessDenied(AuthorityError):
    pass


class ApprovalRequired(AuthorityError):
    pass


class GrantInvalid(AuthorityError):
    pass
