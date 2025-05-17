from flask import Blueprint, request, jsonify
import jwt
from datetime import datetime
import uuid
import json
from models import db, Agent, Attestation
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

attestation_bp = Blueprint('attestation', __name__)

# In a production system, these would be loaded from a secure storage
# For demo purposes, we're generating them here
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

# Generate a key pair for demo purposes
PRIVATE_KEY, PUBLIC_KEY = generate_key_pair()

@attestation_bp.route('/', methods=['GET'])
def get_attestation_info():
    """Get attestation information and requirements"""
    return jsonify({
        "supported_formats": [
            "urn:ietf:params:oauth:token-type:eat",
            "TPM2-Quote",
            "SGX-Quote"
        ],
        "verification_methods": [
            "signature",
            "nonce-challenge"
        ],
        "attestation_endpoint": "/api/attestation/verify"
    }), 200

@attestation_bp.route('/agent/<agent_id>', methods=['GET'])
@attestation_bp.route('/agent/<agent_id>/', methods=['GET'])  # Also handle with trailing slash
def get_agent_attestations(agent_id):
    """Get attestations for a specific agent"""
    print(f"Getting attestations for agent: {agent_id}")
    
    # Get authorization token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    print(f"Token provided: {token[:10]}...")
    
    try:
        # Decode token to get user ID or agent ID
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
        requester_id = payload['sub']
        print(f"Token decoded, requester ID: {requester_id}")
        
        # Check if this is an agent token by looking for OIDC-A claims
        is_agent_token = 'agent_type' in payload and 'delegator_sub' in payload
        
        if is_agent_token:
            print(f"This is an agent token for agent: {requester_id}")
            # If it's the agent's own token, allow access
            if requester_id == agent_id:
                print(f"Agent is accessing its own attestations, authorized")
                # Continue to return attestations
            else:
                print(f"Agent {requester_id} is not authorized to access attestations for agent {agent_id}")
                return jsonify({"error": "Unauthorized"}), 403
        else:
            # Regular user token
            print(f"This is a user token for user: {requester_id}")
            # Get agent
            agent = Agent.query.filter_by(id=agent_id).first()
            
            if not agent:
                print(f"Agent not found: {agent_id}")
                return jsonify({"error": "Agent not found"}), 404
            
            # Check if user owns the agent
            if agent.owner_id != requester_id:
                print(f"User {requester_id} does not own agent {agent_id}")
                return jsonify({"error": "Unauthorized"}), 403
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    # Get attestations for the agent
    attestations = Attestation.query.filter_by(agent_id=agent_id).all()
    
    # Convert to list of dictionaries
    attestation_list = []
    for attestation in attestations:
        attestation_dict = {
            "id": attestation.id,
            "agent_id": attestation.agent_id,
            "attestation_type": attestation.attestation_type,
            "attestation_data": attestation.attestation_data,
            "status": attestation.status,
            "verified_at": attestation.verified_at.isoformat() if attestation.verified_at else None,
            "created_at": attestation.created_at.isoformat()
        }
        attestation_list.append(attestation_dict)
    
    return jsonify(attestation_list), 200

@attestation_bp.route('/verify', methods=['POST'])
def verify_attestation():
    """Verify agent attestation evidence"""
    data = request.get_json()
    
    # Validate required fields
    if not data.get('agent_id') or not data.get('attestation'):
        return jsonify({"error": "Missing required fields"}), 400
    
    agent_id = data.get('agent_id')
    attestation_data = data.get('attestation')
    
    # Get agent
    agent = Agent.query.filter_by(id=agent_id).first()
    
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    
    # Validate attestation format
    if not attestation_data.get('format') or not attestation_data.get('token'):
        return jsonify({"error": "Invalid attestation data"}), 400
    
    # Verify attestation based on format
    attestation_format = attestation_data.get('format')
    attestation_token = attestation_data.get('token')
    
    verification_result = False
    verification_details = {}
    
    if attestation_format == 'urn:ietf:params:oauth:token-type:eat':
        # Verify EAT token
        try:
            # In a real implementation, this would use proper JWT validation
            # with the correct keys for the specific agent provider
            payload = jwt.decode(attestation_token, options={"verify_signature": False})
            
            # Check required claims
            if not payload.get('iat') or not payload.get('iss'):
                verification_result = False
                verification_details = {"error": "Missing required claims in attestation token"}
            else:
                # Verify issuer is trusted
                if payload.get('iss') == agent.agent_provider:
                    verification_result = True
                    verification_details = {
                        "issuer": payload.get('iss'),
                        "issued_at": datetime.fromtimestamp(payload.get('iat')).isoformat(),
                        "claims": payload
                    }
                else:
                    verification_result = False
                    verification_details = {"error": "Untrusted issuer"}
        except Exception as e:
            verification_result = False
            verification_details = {"error": str(e)}
    
    elif attestation_format == 'TPM2-Quote' or attestation_format == 'SGX-Quote':
        # For demo purposes, we'll just check if the token contains the expected agent info
        # In a real implementation, this would involve proper TPM or SGX quote validation
        if agent.instance_id in attestation_token and agent.agent_provider in attestation_token:
            verification_result = True
            verification_details = {
                "platform": attestation_format.split('-')[0],
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            verification_result = False
            verification_details = {"error": "Invalid attestation token"}
    
    else:
        return jsonify({"error": "Unsupported attestation format"}), 400
    
    # Store attestation result
    attestation = Attestation.query.filter_by(agent_id=agent_id).first()
    
    if attestation:
        # Update existing attestation
        attestation.format = attestation_format
        attestation.token = attestation_token
        attestation.verified = verification_result
        attestation.verification_timestamp = datetime.utcnow()
    else:
        # Create new attestation
        attestation = Attestation(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            format=attestation_format,
            token=attestation_token,
            verified=verification_result,
            verification_timestamp=datetime.utcnow()
        )
        db.session.add(attestation)
    
    # Update agent trust level if verification was successful
    if verification_result:
        agent.trust_level = 'verified'
    else:
        agent.trust_level = 'unverified'
    
    db.session.commit()
    
    return jsonify({
        "verified": verification_result,
        "agent_id": agent_id,
        "agent_provider": agent.agent_provider,
        "agent_model": agent.agent_model,
        "agent_version": agent.agent_version,
        "attestation_format": attestation_format,
        "verification_timestamp": datetime.utcnow().isoformat(),
        "details": verification_details
    }), 200

@attestation_bp.route('/nonce', methods=['GET'])
def get_nonce():
    """Get a nonce for attestation challenge"""
    # Generate a random nonce
    nonce = str(uuid.uuid4())
    
    # In a real implementation, store this nonce with an expiry time
    # and associate it with the requesting client
    
    return jsonify({
        "nonce": nonce,
        "expires_in": 300  # 5 minutes
    }), 200

@attestation_bp.route('/keys', methods=['GET'])
def get_verification_keys():
    """Get public keys for verifying attestation signatures"""
    # In a real implementation, this would return the actual verification keys
    # for different agent providers and attestation formats
    
    return jsonify({
        "keys": [
            {
                "kid": "default-key",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "...",  # Base64URL-encoded modulus
                "e": "AQAB"  # Base64URL-encoded exponent
            }
        ]
    }), 200
