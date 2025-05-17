from flask import Blueprint, request, jsonify, url_for
import os

discovery_bp = Blueprint('discovery', __name__)

@discovery_bp.route('/openid-configuration', methods=['GET'])
def openid_configuration():
    """OpenID Connect Discovery endpoint"""
    base_url = request.host_url.rstrip('/')
    
    return jsonify({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/api/auth/authorize",
        "token_endpoint": f"{base_url}/api/auth/token",
        "userinfo_endpoint": f"{base_url}/api/users/me",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "registration_endpoint": f"{base_url}/api/clients/register",
        "scopes_supported": [
            "openid", "profile", "email", "agent"
        ],
        "response_types_supported": [
            "code", "token", "id_token", "code token", "code id_token", 
            "token id_token", "code token id_token"
        ],
        "grant_types_supported": [
            "authorization_code", "implicit", "refresh_token", 
            "client_credentials", "password"
        ],
        "subject_types_supported": ["public", "pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", 
            "client_secret_jwt", "private_key_jwt"
        ],
        "claims_supported": [
            "sub", "iss", "auth_time", "acr", "name", "email", 
            "email_verified", "locale", "picture"
        ],
        
        # OIDC-A specific extensions
        "agent_attestation_endpoint": f"{base_url}/api/attestation/verify",
        "agent_capabilities_endpoint": f"{base_url}/.well-known/agent-capabilities",
        "agent_claims_supported": [
            "agent_type", "agent_model", "agent_version", "agent_provider", 
            "agent_instance_id", "delegator_sub", "delegation_chain", 
            "delegation_purpose", "delegation_constraints", "agent_capabilities", 
            "agent_trust_level", "agent_attestation", "agent_context_id"
        ],
        "agent_types_supported": [
            "assistant", "retrieval", "coding", "domain_specific", 
            "autonomous", "supervised"
        ],
        "delegation_methods_supported": [
            "chain", "direct"
        ],
        "attestation_formats_supported": [
            "urn:ietf:params:oauth:token-type:eat",
            "TPM2-Quote",
            "SGX-Quote"
        ],
        "attestation_verification_keys_endpoint": f"{base_url}/api/attestation/keys"
    }), 200

@discovery_bp.route('/jwks.json', methods=['GET'])
def jwks():
    """JSON Web Key Set endpoint"""
    # In a real implementation, this would return the actual JWK set
    # For demo purposes, we're returning a mock JWK set
    return jsonify({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "default-key",
                "n": "...",  # Base64URL-encoded modulus
                "e": "AQAB",  # Base64URL-encoded exponent
                "alg": "RS256"
            }
        ]
    }), 200

@discovery_bp.route('/agent-capabilities', methods=['GET'])
def agent_capabilities():
    """Agent capabilities discovery endpoint"""
    return jsonify({
        "capabilities": [
            {
                "id": "text_generation",
                "description": "Generate text based on prompts"
            },
            {
                "id": "code_generation",
                "description": "Generate and analyze code"
            },
            {
                "id": "retrieval",
                "description": "Retrieve information from documents or knowledge bases"
            },
            {
                "id": "email:read",
                "description": "Read emails from user's inbox"
            },
            {
                "id": "email:draft",
                "description": "Create email drafts"
            },
            {
                "id": "calendar:view",
                "description": "View calendar events"
            },
            {
                "id": "calendar:create",
                "description": "Create calendar events"
            }
        ],
        "supported_constraints": [
            {
                "id": "max_tokens",
                "description": "Maximum number of tokens to generate",
                "type": "integer"
            },
            {
                "id": "allowed_tools",
                "description": "List of tools the agent is allowed to use",
                "type": "array"
            },
            {
                "id": "max_duration",
                "description": "Maximum duration of the delegation in seconds",
                "type": "integer"
            },
            {
                "id": "allowed_resources",
                "description": "List of resources the agent is allowed to access",
                "type": "array"
            }
        ]
    }), 200
