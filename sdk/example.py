"""
Example usage of the MCP Auth SDK.

This script demonstrates how to use the MCP Auth SDK to authenticate
agents and access MCP server resources using the OIDC-A specification.
"""

import os
import json
import time
from dotenv import load_dotenv

# Import the MCP Auth SDK
from mcp_auth_sdk import (
    AuthClient,
    AgentClient,
    AttestationClient,
    DelegationChain,
    DelegationStep
)

# Load environment variables
load_dotenv()

# Configuration
AUTH_SERVER_URL = os.getenv('AUTH_SERVER_URL', 'http://localhost:5000')
USERNAME = os.getenv('USERNAME', 'test_user')
PASSWORD = os.getenv('PASSWORD', 'password')


def main():
    """
    Main function demonstrating the MCP Auth SDK.
    """
    print("MCP Auth SDK Example")
    print("===================")
    
    # Step 1: Create an AuthClient and authenticate
    print("\n1. Authenticating user...")
    auth_client = AuthClient(AUTH_SERVER_URL)
    
    try:
        # Login with username and password
        tokens = auth_client.login_with_password(USERNAME, PASSWORD)
        print(f"  ✓ Authentication successful")
        print(f"  ✓ Access token: {tokens['access_token'][:20]}...")
        
        # Get user info
        user_info = auth_client.get_user_info()
        print(f"  ✓ Logged in as: {user_info['user']['username']}")
    except Exception as e:
        print(f"  ✗ Authentication failed: {str(e)}")
        return
    
    # Step 2: Create an agent
    print("\n2. Creating an agent...")
    agent_client = AgentClient(
        auth_client=auth_client,
        agent_instance_id=f"example-agent-{int(time.time())}",
        agent_type="assistant",
        agent_model="gpt-4",
        agent_version="2025-03",
        agent_provider="openai.com",
        capabilities=["text_generation", "code_generation"]
    )
    
    try:
        agent_data = agent_client.register_agent()
        print(f"  ✓ Agent created successfully")
        print(f"  ✓ Agent ID: {agent_data['id']}")
        print(f"  ✓ Agent type: {agent_data['agent_type']}")
        print(f"  ✓ Agent model: {agent_data['agent_model']}")
    except Exception as e:
        print(f"  ✗ Agent creation failed: {str(e)}")
        return
    
    # Step 3: Generate an agent token
    print("\n3. Generating agent token...")
    try:
        token_data = agent_client.get_agent_token(
            scope="email profile calendar",
            purpose="Email management assistant"
        )
        print(f"  ✓ Agent token generated successfully")
        print(f"  ✓ Access token: {token_data['access_token'][:20]}...")
        
        # Validate the token
        token_claims = agent_client.validate_agent_token()
        print(f"  ✓ Token validated successfully")
        print(f"  ✓ Agent type: {token_claims['agent_type']}")
        print(f"  ✓ Agent provider: {token_claims['agent_provider']}")
        print(f"  ✓ Delegator: {token_claims['delegator_sub']}")
    except Exception as e:
        print(f"  ✗ Token generation failed: {str(e)}")
    
    # Step 4: Verify attestation (mock example)
    print("\n4. Verifying attestation...")
    try:
        # In a real scenario, you would generate actual attestation evidence
        # Here we're using a mock token for demonstration
        mock_attestation_token = json.dumps({
            "iss": "openai.com",
            "sub": agent_client.agent_instance_id,
            "iat": int(time.time()),
            "measurements": {
                "model_hash": "sha256:1234567890abcdef",
                "version": agent_client.agent_version
            }
        })
        
        attestation_result = agent_client.verify_attestation(
            attestation_format="urn:ietf:params:oauth:token-type:eat",
            attestation_token=mock_attestation_token
        )
        
        print(f"  ✓ Attestation verification result: {attestation_result['verified']}")
        print(f"  ✓ Verification timestamp: {attestation_result['verification_timestamp']}")
    except Exception as e:
        print(f"  ✗ Attestation verification failed: {str(e)}")
    
    # Step 5: Create a delegation to another agent
    print("\n5. Creating a delegation to another agent...")
    try:
        # First, create another agent to delegate to
        second_agent = AgentClient(
            auth_client=auth_client,
            agent_instance_id=f"delegate-agent-{int(time.time())}",
            agent_type="retrieval",
            agent_model="gpt-4",
            agent_version="2025-03",
            agent_provider="openai.com",
            capabilities=["retrieval"]
        )
        second_agent_data = second_agent.register_agent()
        print(f"  ✓ Second agent created with ID: {second_agent_data['id']}")
        
        # Create delegation
        delegation_data = agent_client.create_delegation(
            delegatee_id=second_agent_data['id'],
            scope="calendar:view",
            purpose="Analyze available time slots",
            expires_in=3600,  # 1 hour
            constraints={
                "max_tokens": 1000,
                "allowed_resources": ["/calendar/events"]
            }
        )
        
        print(f"  ✓ Delegation created successfully")
        print(f"  ✓ Delegation ID: {delegation_data['delegation_id']}")
        print(f"  ✓ Access token: {delegation_data['access_token'][:20]}...")
        print(f"  ✓ ID token: {delegation_data['id_token'][:20]}...")
    except Exception as e:
        print(f"  ✗ Delegation creation failed: {str(e)}")
    
    # Step 6: Get delegation chain
    print("\n6. Getting delegation chain...")
    try:
        delegation_chain = agent_client.get_delegation_chain()
        print(f"  ✓ Delegation chain retrieved with {len(delegation_chain)} steps")
        
        for i, step in enumerate(delegation_chain.steps):
            print(f"  ✓ Step {i+1}:")
            print(f"    - From: {step.subject}")
            print(f"    - To: {step.audience}")
            print(f"    - Scope: {step.scope}")
            print(f"    - Purpose: {step.purpose}")
        
        # Validate the chain
        is_valid = delegation_chain.validate()
        print(f"  ✓ Chain validation: {'Valid' if is_valid else 'Invalid'}")
        
        # Get effective scope
        effective_scope = delegation_chain.get_effective_scope()
        print(f"  ✓ Effective scope: {effective_scope}")
    except Exception as e:
        print(f"  ✗ Failed to get delegation chain: {str(e)}")
    
    # Step 7: Access MCP server resources (simulated)
    print("\n7. Accessing MCP server resources (simulated)...")
    print("  ✓ Using agent token to access resources")
    print("  ✓ Scope: calendar:view")
    print("  ✓ Resource: /calendar/events")
    print("  ✓ Successfully retrieved calendar events")
    
    print("\nExample completed successfully!")


if __name__ == "__main__":
    main()
