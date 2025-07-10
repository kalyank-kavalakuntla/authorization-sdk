"""Custom exceptions for the Multitenancy SDK."""

class AuthenticationError(Exception):
    """Raised when authentication fails (e.g., invalid JWT token)."""
    pass

class AuthorizationError(Exception):
    """Raised when authorization fails (e.g., insufficient permissions)."""
    pass

class ApiError(Exception):
    """Raised when API requests fail."""
    pass
