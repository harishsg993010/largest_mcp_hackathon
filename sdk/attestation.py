"""
Attestation module for the MCP Auth SDK.

This module implements the attestation verification functionality
specified in the OpenID Connect for Agents (OIDC-A) 1.0 specification.
"""

import uuid
import requests
from typing import Dict, Optional, Any

from .exceptions import AttestationError, APIError
from .auth_client import AuthClient


class AttestationClient:
    """
    Client for verifying agent attestation evidence.
    
    This client implements the attestation verification functionality
    specified in the OIDC-A 1.0 specification.
    """
    
    def __init__(self, auth_client: AuthClient):
        """
        Initialize the AttestationClient.
        
        Args:
            auth_client: Authenticated AuthClient instance
        """
        self.auth_client = auth_client
    
    def get_attestation_info(self) -> Dict:
        """
        Get information about supported attestation formats and methods.
        
        Returns:
            Dict: Attestation information
        """
        config = self.auth_client.get_openid_configuration()
        attestation_endpoint = config.get('agent_attestation_endpoint')
        
        if not attestation_endpoint:
            attestation_endpoint = f"{self.auth_client.auth_server_url}/api/attestation"
        
        response = self.auth_client.request('GET', attestation_endpoint)
        return response.json()
    
    def verify_attestation(
        self,
        agent_id: str,
        attestation_format: str,
        attestation_token: str
    ) -> Dict:
        """
        Verify agent attestation evidence.
        
        Args:
            agent_id: ID of the agent to verify
            attestation_format: Format of the attestation evidence
            attestation_token: Attestation token or evidence
            
        Returns:
            Dict: Attestation verification result
        """
        config = self.auth_client.get_openid_configuration()
        attestation_endpoint = config.get('agent_attestation_endpoint')
        
        if not attestation_endpoint:
            attestation_endpoint = f"{self.auth_client.auth_server_url}/api/attestation/verify"
        
        data = {
            'agent_id': agent_id,
            'attestation': {
                'format': attestation_format,
                'token': attestation_token
            }
        }
        
        try:
            response = self.auth_client.request('POST', attestation_endpoint, json=data)
            return response.json()
        except APIError as e:
            raise AttestationError(f"Attestation verification failed: {str(e)}")
    
    def get_nonce(self) -> str:
        """
        Get a nonce for attestation challenge.
        
        Returns:
            str: Nonce value
        """
        config = self.auth_client.get_openid_configuration()
        nonce_endpoint = config.get('agent_attestation_nonce_endpoint')
        
        if not nonce_endpoint:
            nonce_endpoint = f"{self.auth_client.auth_server_url}/api/attestation/nonce"
        
        try:
            response = self.auth_client.request('GET', nonce_endpoint)
            return response.json().get('nonce')
        except APIError as e:
            raise AttestationError(f"Failed to get attestation nonce: {str(e)}")
    
    def get_verification_keys(self) -> Dict:
        """
        Get public keys for verifying attestation signatures.
        
        Returns:
            Dict: Dictionary of verification keys
        """
        config = self.auth_client.get_openid_configuration()
        keys_endpoint = config.get('attestation_verification_keys_endpoint')
        
        if not keys_endpoint:
            keys_endpoint = f"{self.auth_client.auth_server_url}/api/attestation/keys"
        
        try:
            response = self.auth_client.request('GET', keys_endpoint)
            return response.json()
        except APIError as e:
            raise AttestationError(f"Failed to get verification keys: {str(e)}")


class AttestationEvidence:
    """
    Represents attestation evidence for an agent.
    
    This class provides methods for creating and validating
    attestation evidence in various formats.
    """
    
    def __init__(
        self,
        format: str,
        token: str,
        timestamp: Optional[int] = None
    ):
        """
        Initialize attestation evidence.
        
        Args:
            format: Format of the attestation evidence
            token: Attestation token or evidence
            timestamp: Timestamp when the evidence was created
        """
        self.format = format
        self.token = token
        self.timestamp = timestamp
    
    def to_dict(self) -> Dict:
        """
        Convert attestation evidence to a dictionary.
        
        Returns:
            Dict: Dictionary representation of the attestation evidence
        """
        result = {
            'format': self.format,
            'token': self.token
        }
        
        if self.timestamp:
            result['timestamp'] = self.timestamp
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AttestationEvidence':
        """
        Create attestation evidence from a dictionary.
        
        Args:
            data: Dictionary containing attestation evidence
            
        Returns:
            AttestationEvidence: Attestation evidence instance
        """
        return cls(
            format=data.get('format'),
            token=data.get('token'),
            timestamp=data.get('timestamp')
        )
