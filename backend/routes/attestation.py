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

@attestation_bp.route('/', methods=['POST'])
@attestation_bp.route('', methods=['POST'])  # Also handle without trailing slash
def create_attestation():
    """Create a new attestation for an agent"""
    try:
        # Get request data
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Validate required fields
        required_fields = ['agent_id', 'format', 'token']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        agent_id = data['agent_id']
        attestation_format = data['format']
        attestation_token = data['token']
        
        # Check if agent exists
        agent = Agent.query.filter_by(id=agent_id).first()
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
        
        # Generate a unique ID for the attestation
        attestation_id = str(uuid.uuid4())
        
        # Create new attestation
        attestation = Attestation(
            id=attestation_id,
            agent_id=agent_id,
            format=attestation_format,
            token=attestation_token,
            verified=False,  # Not verified yet
            timestamp=datetime.utcnow()
        )
        
        # Save to database
        db.session.add(attestation)
        db.session.commit()
        
        # Return the created attestation
        return jsonify({
            "id": attestation.id,
            "agent_id": attestation.agent_id,
            "format": attestation.format,
            "verified": attestation.verified,
            "timestamp": attestation.timestamp.isoformat()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating attestation: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

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
            "format": attestation.format,  # Use format instead of attestation_type
            "token": attestation.token,  # Use token instead of attestation_data
            "verified": attestation.verified,  # Use verified instead of status
            "verification_timestamp": attestation.verification_timestamp.isoformat() if attestation.verification_timestamp else None,  # Use verification_timestamp instead of verified_at
            "timestamp": attestation.timestamp.isoformat() if attestation.timestamp else None  # Use timestamp instead of created_at
        }
        attestation_list.append(attestation_dict)
    
    return jsonify(attestation_list), 200

@attestation_bp.route('/verify', methods=['POST'])
def verify_attestation():
    """Verify agent attestation evidence"""
    print("Attestation verification request received")
    data = request.get_json()
    print(f"Request data: {data}")
    
    # Validate required fields
    if not data.get('agent_id'):
        print("Missing agent_id field")
        return jsonify({"error": "Missing agent_id field"}), 400
    
    if not data.get('attestation'):
        print("Missing attestation field")
        return jsonify({"error": "Missing attestation field"}), 400
    
    agent_id = data.get('agent_id')
    attestation_data = data.get('attestation')
    
    # Get agent
    agent = Agent.query.filter_by(id=agent_id).first()
    
    if not agent:
        print(f"Agent not found: {agent_id}")
        return jsonify({"error": "Agent not found"}), 404
    
    # Validate attestation format
    if not attestation_data.get('format'):
        print("Missing attestation format")
        return jsonify({"error": "Missing attestation format"}), 400
        
    # Check for token field
    attestation_token = attestation_data.get('token')
    
    if not attestation_token:
        print("Missing attestation token")
        return jsonify({"error": "Missing attestation token"}), 400
        
    # Get format
    attestation_format = attestation_data.get('format')
    print(f"Attestation format: {attestation_format}")
    print(f"Attestation token: {attestation_token}")
    
    # Verify attestation based on format
    verification_result = False
    verification_details = {}
    
    # For demo purposes, we'll implement a simplified verification process
    # In a real implementation, this would involve proper cryptographic validation
    try:
        print(f"Verifying attestation format: {attestation_format}")
        
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
                verification_details = {"error": f"Error decoding EAT token: {str(e)}"}
        
        elif attestation_format == 'TPM2-Quote' or attestation_format == 'SGX-Quote':
            # For demo purposes, we'll accept any attestation for testing
            # In a real implementation, this would involve proper TPM or SGX quote validation
            print(f"Simulating verification of {attestation_format}")
            
            # For demo, we'll accept the attestation if it contains certain keywords
            if 'sample-attestation' in attestation_token:
                verification_result = True
                verification_details = {
                    "platform": attestation_format.split('-')[0],
                    "timestamp": datetime.utcnow().isoformat(),
                    "note": "This is a simulated verification for demo purposes"
                }
            else:
                verification_result = False
                verification_details = {"error": "Invalid attestation evidence"}
        
        else:
            print(f"Unsupported attestation format: {attestation_format}")
            return jsonify({"error": "Unsupported attestation format"}), 400
            
        print(f"Verification result: {verification_result}")
        print(f"Verification details: {verification_details}")
        
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        verification_result = False
        verification_details = {"error": f"Verification error: {str(e)}"}
    
    # Store attestation result
    print("Storing attestation result")
    
    # Check if an attestation already exists for this agent and format
    attestation = Attestation.query.filter_by(
        agent_id=agent_id, 
        format=attestation_format
    ).first()
    
    try:
        # Generate a unique ID for the attestation
        attestation_id = str(uuid.uuid4())
        
        # Store attestation data using the correct column names
        if not attestation:
            print(f"Creating new attestation record with ID: {attestation_id}")
            attestation = Attestation(
                id=attestation_id,
                agent_id=agent_id,
                format=attestation_format,
                token=attestation_token,
                verified=verification_result,
                verification_timestamp=datetime.utcnow() if verification_result else None,
                timestamp=datetime.utcnow()
            )
            db.session.add(attestation)
        else:
            print(f"Updating existing attestation record: {attestation.id}")
            attestation.format = attestation_format
            attestation.token = attestation_token
            attestation.verified = verification_result
            attestation.verification_timestamp = datetime.utcnow() if verification_result else None
        
        # Update agent trust level if verification was successful
        if verification_result:
            print(f"Updating agent trust level to 'verified'")
            agent.trust_level = 'verified'
        
        # Commit changes to database
        db.session.commit()
        print("Successfully committed attestation to database")
        
        # Prepare response with OIDC-A compliant format
        response = {
            "verification_result": verification_result,
            "verification_details": verification_details,
            "attestation": {
                "id": attestation.id,
                "agent_id": agent_id,
                "format": attestation_format,
                "verified": attestation.verified,
                "verification_timestamp": attestation.verification_timestamp.isoformat() if attestation.verification_timestamp else None,
                "timestamp": attestation.timestamp.isoformat() if attestation.timestamp else None
            },
            "agent": {
                "id": agent.id,
                "agent_type": agent.agent_type,
                "agent_model": agent.agent_model,
                "agent_provider": agent.agent_provider,
                "trust_level": agent.trust_level
            }
        }
        
        # Return success response
        return jsonify(response), 200
        
    except Exception as e:
        # Roll back transaction in case of error
        db.session.rollback()
        print(f"Error storing attestation: {str(e)}")
        return jsonify({
            "error": f"Error storing attestation: {str(e)}",
            "verification_result": verification_result,
            "verification_details": verification_details
        }), 500

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
