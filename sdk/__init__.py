"""
MCP Auth SDK - Client library for MCP server authentication and authorization
implementing OpenID Connect for Agents (OIDC-A) 1.0 specification.
"""

from .auth_client import AuthClient
from .agent_client import AgentClient
from .delegation import DelegationChain, DelegationStep
from .attestation import AttestationClient
from .exceptions import (
    MCPAuthError, 
    AuthenticationError, 
    AuthorizationError, 
    AttestationError,
    DelegationError
)

__version__ = '0.1.0'
__all__ = [
    'AuthClient',
    'AgentClient',
    'AttestationClient',
    'DelegationChain',
    'DelegationStep',
    'MCPAuthError',
    'AuthenticationError',
    'AuthorizationError',
    'AttestationError',
    'DelegationError'
]
