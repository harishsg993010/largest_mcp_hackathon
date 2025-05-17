"""
Agent client for the MCP Auth SDK.

This module implements the OpenID Connect for Agents (OIDC-A) 1.0 specification
for authenticating and managing AI agents.
"""

import json
import time
import uuid
from typing import Dict, List, Optional, Union, Any
import requests
import jwt

from .auth_client import AuthClient
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    AttestationError,
    DelegationError,
    APIError
)
from .attestation import AttestationClient
from .delegation import DelegationChain, DelegationStep


class AgentClient:
    """
    Client for managing AI agents with the MCP Auth Platform.
    
    This client implements the OIDC-A 1.0 specification for agent
    authentication, attestation, and delegation.
    """
    
    def __init__(
        self,
        auth_client: AuthClient,
        agent_id: Optional[str] = None,
        agent_instance_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        agent_model: Optional[str] = None,
        agent_version: Optional[str] = None,
        agent_provider: Optional[str] = None,
        capabilities: Optional[List[str]] = None
    ):
        """
        Initialize the AgentClient.
        
        Args:
            auth_client: Authenticated AuthClient instance
            agent_id: ID of an existing agent (if managing an existing agent)
            agent_instance_id: Unique identifier for this agent instance
            agent_type: Type/class of agent (e.g., "assistant", "retrieval")
            agent_model: Specific model (e.g., "gpt-4", "claude-3-opus")
            agent_version: Version identifier of the agent model
            agent_provider: Organization that provides/hosts the agent
            capabilities: List of agent capabilities
        """
        self.auth_client = auth_client
        self.agent_id = agent_id
        self.agent_instance_id = agent_instance_id
        self.agent_type = agent_type
        self.agent_model = agent_model
        self.agent_version = agent_version
        self.agent_provider = agent_provider
        self.capabilities = capabilities or []
        
        # Agent token storage
        self.agent_token = None
        self.agent_token_claims = None
        
        # Attestation client
        self.attestation_client = AttestationClient(auth_client)
        
        # Delegation chain
        self.delegation_chain = None
    
    def register_agent(self) -> Dict:
        """
        Register a new agent with the MCP Auth Platform.
        
        Returns:
            Dict: Registered agent details
        """
        if not all([self.agent_instance_id, self.agent_type, self.agent_model, self.agent_provider]):
            raise ValueError("agent_instance_id, agent_type, agent_model, and agent_provider are required")
        
        data = {
            'instance_id': self.agent_instance_id,
            'agent_type': self.agent_type,
            'agent_model': self.agent_model,
            'agent_provider': self.agent_provider,
            'capabilities': self.capabilities
        }
        
        if self.agent_version:
            data['agent_version'] = self.agent_version
        
        response = self.auth_client.request('POST', '/api/agents', json=data)
        agent_data = response.json().get('agent')
        
        # Update agent ID
        self.agent_id = agent_data.get('id')
        
        return agent_data
    
    def get_agent_details(self, agent_id: Optional[str] = None) -> Dict:
        """
        Get details about an agent.
        
        Args:
            agent_id: ID of the agent (defaults to this client's agent_id)
            
        Returns:
            Dict: Agent details
        """
        agent_id = agent_id or self.agent_id
        
        if not agent_id:
            raise ValueError("agent_id is required")
        
        response = self.auth_client.request('GET', f'/api/agents/{agent_id}')
        return response.json().get('agent')
    
    def update_agent(self, agent_data: Dict) -> Dict:
        """
        Update agent details.
        
        Args:
            agent_data: Dictionary of agent properties to update
            
        Returns:
            Dict: Updated agent details
        """
        if not self.agent_id:
            raise ValueError("agent_id is required")
        
        response = self.auth_client.request('PUT', f'/api/agents/{self.agent_id}', json=agent_data)
        return response.json().get('agent')
    
    def delete_agent(self) -> bool:
        """
        Delete an agent.
        
        Returns:
            bool: True if deletion was successful
        """
        if not self.agent_id:
            raise ValueError("agent_id is required")
        
        response = self.auth_client.request('DELETE', f'/api/agents/{self.agent_id}')
        return 'message' in response.json()
    
    def get_agent_token(
        self,
        scope: str = "",
        purpose: Optional[str] = None,
        constraints: Optional[Dict] = None
    ) -> Dict:
        """
        Generate a token for this agent.
        
        Args:
            scope: Space-separated list of OAuth scopes
            purpose: Description of the purpose/intent for delegation
            constraints: Dictionary of constraints on the delegation
            
        Returns:
            Dict: Token response containing access_token, etc.
        """
        if not self.agent_id:
            raise ValueError("agent_id is required")
        
        data = {'scope': scope}
        
        if purpose:
            data['purpose'] = purpose
        
        if constraints:
            data['constraints'] = constraints
        
        response = self.auth_client.request(
            'POST', 
            f'/api/agents/{self.agent_id}/token', 
            json=data
        )
        token_data = response.json()
        
        # Store agent token
        self.agent_token = token_data.get('access_token')
        
        # Decode token claims
        try:
            self.agent_token_claims = jwt.decode(
                self.agent_token, 
                options={"verify_signature": False}
            )
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Invalid agent token: {str(e)}")
        
        return token_data
    
    def verify_attestation(
        self,
        attestation_format: str,
        attestation_token: str
    ) -> Dict:
        """
        Verify the agent's attestation evidence.
        
        Args:
            attestation_format: Format of the attestation evidence
            attestation_token: Attestation token or evidence
            
        Returns:
            Dict: Attestation verification result
        """
        if not self.agent_id:
            raise ValueError("agent_id is required")
        
        return self.attestation_client.verify_attestation(
            self.agent_id,
            attestation_format,
            attestation_token
        )
    
    def get_attestation_nonce(self) -> str:
        """
        Get a nonce for attestation challenge.
        
        Returns:
            str: Nonce value
        """
        return self.attestation_client.get_nonce()
    
    def create_delegation(
        self,
        delegatee_id: str,
        scope: str,
        purpose: Optional[str] = None,
        expires_in: int = 3600,
        constraints: Optional[Dict] = None
    ) -> Dict:
        """
        Create a delegation to another agent.
        
        Args:
            delegatee_id: ID of the agent receiving the delegation
            scope: Space-separated list of OAuth scopes
            purpose: Description of the purpose/intent for delegation
            expires_in: Expiration time in seconds
            constraints: Dictionary of constraints on the delegation
            
        Returns:
            Dict: Delegation response containing tokens and delegation ID
        """
        data = {
            'delegatee_id': delegatee_id,
            'scope': scope,
            'expires_in': expires_in
        }
        
        if purpose:
            data['purpose'] = purpose
        
        if constraints:
            data['constraints'] = constraints
        
        # Use agent token if available, otherwise use user token
        headers = {}
        if self.agent_token:
            headers['Authorization'] = f"Bearer {self.agent_token}"
            response = requests.post(
                f"{self.auth_client.auth_server_url}/api/delegation",
                json=data,
                headers=headers
            )
        else:
            response = self.auth_client.request('POST', '/api/delegation', json=data)
        
        if response.status_code != 201:
            raise DelegationError(f"Failed to create delegation: {response.text}")
        
        return response.json()
    
    def get_delegation_chain(self) -> DelegationChain:
        """
        Get the delegation chain for this agent.
        
        Returns:
            DelegationChain: The delegation chain
        """
        # Use agent token if available, otherwise use user token
        headers = {}
        if self.agent_token:
            headers['Authorization'] = f"Bearer {self.agent_token}"
            response = requests.get(
                f"{self.auth_client.auth_server_url}/api/delegation/chain",
                headers=headers
            )
        else:
            response = self.auth_client.request('GET', '/api/delegation/chain')
        
        if response.status_code != 200:
            raise DelegationError(f"Failed to get delegation chain: {response.text}")
        
        chain_data = response.json().get('delegation_chain', [])
        
        # Create delegation chain
        steps = []
        for step_data in chain_data:
            step = DelegationStep(
                issuer=step_data.get('iss'),
                subject=step_data.get('sub'),
                audience=step_data.get('aud'),
                delegated_at=step_data.get('delegated_at'),
                scope=step_data.get('scope'),
                purpose=step_data.get('purpose'),
                constraints=step_data.get('constraints'),
                jti=step_data.get('jti')
            )
            steps.append(step)
        
        self.delegation_chain = DelegationChain(steps)
        return self.delegation_chain
    
    def validate_agent_token(self, token: Optional[str] = None) -> Dict:
        """
        Validate an agent token and return its claims.
        
        Args:
            token: Agent token to validate (if not provided, uses stored token)
            
        Returns:
            Dict: Agent token claims
        """
        token = token or self.agent_token
        
        if not token:
            raise AuthenticationError("No agent token available")
        
        try:
            # In a production environment, you would verify the signature
            # using the JWKS from the auth server
            claims = jwt.decode(token, options={"verify_signature": False})
            
            # Validate expiration
            if 'exp' in claims and claims['exp'] < time.time():
                raise AuthenticationError("Agent token has expired")
            
            # Validate agent-specific claims
            required_claims = ['agent_type', 'agent_model', 'agent_provider', 'agent_instance_id']
            for claim in required_claims:
                if claim not in claims:
                    raise AuthenticationError(f"Agent token missing required claim: {claim}")
            
            return claims
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Invalid agent token: {str(e)}")
    
    def is_agent_token_valid(self) -> bool:
        """
        Check if the agent token is valid.
        
        Returns:
            bool: True if the agent token is valid
        """
        if not self.agent_token:
            return False
        
        try:
            self.validate_agent_token()
            return True
        except AuthenticationError:
            return False
    
    def get_agent_capabilities(self) -> List[Dict]:
        """
        Get the list of supported agent capabilities from the server.
        
        Returns:
            List[Dict]: List of capability objects with id and description
        """
        config = self.auth_client.get_openid_configuration()
        capabilities_endpoint = config.get('agent_capabilities_endpoint')
        
        if not capabilities_endpoint:
            capabilities_endpoint = f"{self.auth_client.auth_server_url}/.well-known/agent-capabilities"
        
        response = requests.get(capabilities_endpoint)
        
        if response.status_code != 200:
            raise APIError(f"Failed to get agent capabilities: {response.text}",
                          response.status_code, response)
        
        return response.json().get('capabilities', [])
    
    def get_supported_constraints(self) -> List[Dict]:
        """
        Get the list of supported delegation constraints from the server.
        
        Returns:
            List[Dict]: List of constraint objects with id, description, and type
        """
        config = self.auth_client.get_openid_configuration()
        capabilities_endpoint = config.get('agent_capabilities_endpoint')
        
        if not capabilities_endpoint:
            capabilities_endpoint = f"{self.auth_client.auth_server_url}/.well-known/agent-capabilities"
        
        response = requests.get(capabilities_endpoint)
        
        if response.status_code != 200:
            raise APIError(f"Failed to get supported constraints: {response.text}",
                          response.status_code, response)
        
        return response.json().get('supported_constraints', [])
