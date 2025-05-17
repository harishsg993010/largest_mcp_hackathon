#!/usr/bin/env python
"""
OIDC-A Token Test Script
This script demonstrates how to use an OIDC-A token to access protected resources.
"""

import requests
import json
import sys

# The token generated from the agent-details page
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlNGE1ODhjMC05OTQ0LTRiNjktOTlhYi1kMWRkYzQ2Zjc5YWEiLCJpYXQiOjE3NDc1MTE5OTYsImV4cCI6MTc0NzUxNTU5NiwiYWdlbnRfdHlwZSI6ImFzc2lzdGFudCIsImFnZW50X21vZGVsIjoiZ3B0NCIsImFnZW50X3ZlcnNpb24iOiIxLjAiLCJhZ2VudF9wcm92aWRlciI6ImV4cGVyaWVtZW50LmNvbSIsImFnZW50X2luc3RhbmNlX2lkIjoibWNwMSIsImRlbGVnYXRvcl9zdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJkZWxlZ2F0aW9uX3B1cnBvc2UiOiJBY2Nlc3MgTUNQIHJlc291cmNlcyIsImFnZW50X2NhcGFiaWxpdGllcyI6WyJ0ZXh0X2dlbmVyYXRpb24iXSwiYWdlbnRfdHJ1c3RfbGV2ZWwiOiJ1bnZlcmlmaWVkIn0.4i5vubZ2MEVB2onarVCATbfAlpHeZGzeN3Vd5rp91r8"

# Base URL for the API
BASE_URL = "http://localhost:5000/api"

def print_token_info():
    """Print the decoded token information"""
    import jwt
    
    try:
        # Decode the token without verification (just to see the contents)
        decoded = jwt.decode(TOKEN, options={"verify_signature": False})
        print("\n=== OIDC-A Token Information ===")
        print(json.dumps(decoded, indent=2))
        print("\nToken contains the following OIDC-A claims:")
        
        # Check for OIDC-A specific claims
        oidc_a_claims = [
            "agent_type", "agent_model", "agent_provider", 
            "agent_instance_id", "delegator_sub", "delegation_purpose",
            "agent_capabilities", "agent_trust_level"
        ]
        
        for claim in oidc_a_claims:
            if claim in decoded:
                print(f"✓ {claim}: {decoded[claim]}")
            else:
                print(f"✗ {claim}: Not present")
                
        print("\n")
    except Exception as e:
        print(f"Error decoding token: {e}")

def test_agent_info():
    """Test getting agent information using the token"""
    agent_id = "e4a588c0-9944-4b69-99ab-d1ddc46f79aa"  # This should match the 'sub' in the token
    
    print(f"Testing agent info retrieval for agent: {agent_id}")
    
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{BASE_URL}/agents/{agent_id}/", headers=headers)
        
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            print("Successfully retrieved agent info:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Failed to retrieve agent info: {response.text}")
    except Exception as e:
        print(f"Error making request: {e}")

def test_attestations():
    """Test getting attestations using the token"""
    agent_id = "e4a588c0-9944-4b69-99ab-d1ddc46f79aa"
    
    print(f"Testing attestation retrieval for agent: {agent_id}")
    
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{BASE_URL}/attestation/agent/{agent_id}/", headers=headers)
        
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            print("Successfully retrieved attestations:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Failed to retrieve attestations: {response.text}")
    except Exception as e:
        print(f"Error making request: {e}")

def test_delegations():
    """Test getting delegations using the token"""
    agent_id = "e4a588c0-9944-4b69-99ab-d1ddc46f79aa"
    
    print(f"Testing delegation retrieval for agent: {agent_id}")
    
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(
            f"{BASE_URL}/delegation/?delegatee_id={agent_id}&delegatee_type=agent", 
            headers=headers
        )
        
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            print("Successfully retrieved delegations:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Failed to retrieve delegations: {response.text}")
    except Exception as e:
        print(f"Error making request: {e}")

def main():
    """Main function to run all tests"""
    print("=== OIDC-A Token Test ===")
    print("This script tests using an OIDC-A token to access protected resources\n")
    
    # Print token information
    print_token_info()
    
    # Run tests
    test_agent_info()
    print("\n" + "-" * 50 + "\n")
    
    test_attestations()
    print("\n" + "-" * 50 + "\n")
    
    test_delegations()

if __name__ == "__main__":
    main()
