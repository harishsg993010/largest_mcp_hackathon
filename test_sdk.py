#!/usr/bin/env python
"""
OIDC-A SDK Test Script
This script demonstrates how to use the SDK to interact with the OIDC-A server.
"""

import os
import sys
import json
import requests
import time

# Configuration
AUTH_SERVER_URL = "http://localhost:5000/api"
AGENT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlNGE1ODhjMC05OTQ0LTRiNjktOTlhYi1kMWRkYzQ2Zjc5YWEiLCJpYXQiOjE3NDc1MTE5OTYsImV4cCI6MTc0NzUxNTU5NiwiYWdlbnRfdHlwZSI6ImFzc2lzdGFudCIsImFnZW50X21vZGVsIjoiZ3B0NCIsImFnZW50X3ZlcnNpb24iOiIxLjAiLCJhZ2VudF9wcm92aWRlciI6ImV4cGVyaWVtZW50LmNvbSIsImFnZW50X2luc3RhbmNlX2lkIjoibWNwMSIsImRlbGVnYXRvcl9zdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJkZWxlZ2F0aW9uX3B1cnBvc2UiOiJBY2Nlc3MgTUNQIHJlc291cmNlcyIsImFnZW50X2NhcGFiaWxpdGllcyI6WyJ0ZXh0X2dlbmVyYXRpb24iXSwiYWdlbnRfdHJ1c3RfbGV2ZWwiOiJ1bnZlcmlmaWVkIn0.4i5vubZ2MEVB2onarVCATbfAlpHeZGzeN3Vd5rp91r8"
AGENT_ID = "e4a588c0-9944-4b69-99ab-d1ddc46f79aa"

# Simple implementation of the SDK classes for testing
class SimpleAuthClient:
    """Simplified AuthClient for testing"""
    
    def __init__(self, auth_server_url, token=None):
        self.auth_server_url = auth_server_url.rstrip('/')
        self.token = token
        
    def request(self, method, url, **kwargs):
        """Make an authenticated request"""
        headers = kwargs.get('headers', {})
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        kwargs['headers'] = headers
        response = requests.request(method, url, **kwargs)
        
        if response.status_code >= 400:
            raise Exception(f"{response.status_code} {response.reason}: {response.text}")
            
        return response
        
class SimpleAttestationClient:
    """Simplified AttestationClient for testing"""
    
    def __init__(self, auth_client):
        self.auth_client = auth_client
        
    def get_attestation_info(self):
        """Get attestation information"""
        url = f"{self.auth_client.auth_server_url}/attestation"
        response = self.auth_client.request('GET', url)
        return response.json()
        
    def get_agent_attestations(self, agent_id):
        """Get attestations for an agent"""
        url = f"{self.auth_client.auth_server_url}/attestation/agent/{agent_id}/"
        response = self.auth_client.request('GET', url)
        return response.json()
        
    def verify_attestation(self, agent_id, attestation_format, attestation_data):
        """Verify an attestation"""
        url = f"{self.auth_client.auth_server_url}/attestation/verify"
        data = {
            'agent_id': agent_id,
            'attestation': {
                'format': attestation_format,
                'data': attestation_data
            }
        }
        response = self.auth_client.request('POST', url, json=data)
        return response.json()

def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 50)
    print(f"  {title}")
    print("=" * 50)

def test_auth_client():
    """Test the AuthClient functionality"""
    print_section("Testing AuthClient")
    
    # Initialize the auth client with the agent token
    auth_client = SimpleAuthClient(AUTH_SERVER_URL, AGENT_TOKEN)
    print("✓ Initialized AuthClient with agent token")
    
    # Test making an authenticated request
    try:
        # Get the agent's own information
        response = auth_client.request('GET', f"{AUTH_SERVER_URL}/agents/{AGENT_ID}/")
        agent_info = response.json()
        
        print("✓ Successfully made authenticated request")
        print(f"Agent info: {json.dumps(agent_info, indent=2)}")
        
        # Verify the agent information matches the token claims
        if agent_info.get('agent', {}).get('id') == AGENT_ID:
            print("✓ Agent ID in response matches token subject")
        else:
            print("✗ Agent ID mismatch")
            
        return auth_client
    except Exception as e:
        print(f"✗ Error making authenticated request: {str(e)}")
        return None

def test_attestation_client(auth_client):
    """Test the AttestationClient functionality"""
    print_section("Testing AttestationClient")
    
    if not auth_client:
        print("✗ Cannot test AttestationClient without valid AuthClient")
        return
    
    # Initialize the attestation client
    attestation_client = SimpleAttestationClient(auth_client)
    print("✓ Initialized AttestationClient")
    
    # Get attestation information
    try:
        attestation_info = attestation_client.get_attestation_info()
        print("✓ Successfully retrieved attestation information")
        print(f"Supported formats: {attestation_info.get('supported_formats', [])}")
        print(f"Verification methods: {attestation_info.get('verification_methods', [])}")
    except Exception as e:
        print(f"✗ Error getting attestation information: {str(e)}")
    
    # Get agent attestations
    try:
        attestations = attestation_client.get_agent_attestations(AGENT_ID)
        print("✓ Successfully retrieved agent attestations")
        print(f"Attestations: {json.dumps(attestations, indent=2)}")
    except Exception as e:
        print(f"✗ Error getting agent attestations: {str(e)}")
    
    # Create a sample attestation evidence
    print("\nCreating and verifying attestation evidence:")
    
    # In a real scenario, this would be generated by the agent's TPM or other secure element
    attestation_data = {
        "format": "TPM2-Quote",
        "data": "sample-attestation-evidence-123",
        "timestamp": int(time.time())
    }
    print("✓ Created attestation evidence")
    print(f"Evidence: {json.dumps(attestation_data, indent=2)}")
    
    # Try to verify the attestation
    try:
        # This might fail if the endpoint is not fully implemented in the backend
        verification_result = attestation_client.verify_attestation(
            AGENT_ID, 
            attestation_data['format'],
            attestation_data['data']
        )
        print("✓ Successfully verified attestation")
        print(f"Verification result: {json.dumps(verification_result, indent=2)}")
    except Exception as e:
        print(f"✗ Error verifying attestation: {str(e)}")
        print("This is expected if the verification endpoint is not fully implemented")
    
    print("\nIn a real implementation:")
    print("1. The attestation would be generated by the agent's secure hardware")
    print("2. The attestation would be verified by the server against trusted roots")
    print("3. If valid, the agent's trust level would be updated to 'verified'")
    print("4. The agent would receive a new token with the updated trust level claim")

def main():
    """Main function to run all tests"""
    print("OIDC-A SDK Test")
    print("This script tests the SDK integration with the OIDC-A server\n")
    
    # Test auth client
    auth_client = test_auth_client()
    
    # Test attestation client
    test_attestation_client(auth_client)
    
    print("\nSDK Test Complete")

if __name__ == "__main__":
    import time  # Import here to avoid conflict with the earlier mention
    main()
