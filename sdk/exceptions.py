"""
Exceptions for the MCP Auth SDK.
"""

class MCPAuthError(Exception):
    """Base exception for all MCP Auth SDK errors."""
    pass


class AuthenticationError(MCPAuthError):
    """Exception raised for authentication errors."""
    pass


class AuthorizationError(MCPAuthError):
    """Exception raised for authorization errors."""
    pass


class AttestationError(MCPAuthError):
    """Exception raised for attestation errors."""
    pass


class DelegationError(MCPAuthError):
    """Exception raised for delegation errors."""
    pass


class ValidationError(MCPAuthError):
    """Exception raised for validation errors."""
    pass


class APIError(MCPAuthError):
    """Exception raised for API errors."""
    
    def __init__(self, message, status_code=None, response=None):
        self.status_code = status_code
        self.response = response
        super().__init__(message)
