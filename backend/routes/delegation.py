from flask import Blueprint, request, jsonify
import jwt
from datetime import datetime, timedelta
import uuid
import json
from models import db, User, Agent, Delegation, Token

delegation_bp = Blueprint('delegation', __name__)

@delegation_bp.route('/', methods=['GET'])
@delegation_bp.route('', methods=['GET'])  # Also handle without trailing slash
def get_delegations():
    """Get delegations for the authenticated user"""
    # Get user ID from token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode token to get user ID
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
        user_id = payload['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # Get delegations for user
    delegations = Delegation.query.filter_by(delegator_id=user_id, delegator_type='user').all()
    
    return jsonify({
        "delegations": [delegation.to_dict() for delegation in delegations]
    }), 200

@delegation_bp.route('/', methods=['POST'])
@delegation_bp.route('', methods=['POST'])  # Also handle without trailing slash
def create_delegation():
    """Create a new delegation"""
    # Get user ID from token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode token to get user ID
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
        user_id = payload['sub']
        delegator_type = 'user'
        
        # Check if token is for an agent
        if 'agent_instance_id' in payload:
            user_id = payload['delegator_sub']
            delegator_id = payload['sub']
            delegator_type = 'agent'
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # Validate request data
    data = request.get_json()
    
    required_fields = ['delegatee_id', 'scope']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Verify delegatee exists
    delegatee = Agent.query.filter_by(id=data['delegatee_id']).first()
    if not delegatee:
        return jsonify({"error": "Delegatee agent not found"}), 404
    
    # If delegator is an agent, verify it exists and is owned by the user
    if delegator_type == 'agent':
        delegator_agent = Agent.query.filter_by(id=delegator_id).first()
        if not delegator_agent:
            return jsonify({"error": "Delegator agent not found"}), 404
        
        if delegator_agent.owner_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Verify delegator agent has the required scopes
        # In a real implementation, check if the delegator has the scopes it's trying to delegate
    
    # Create new delegation
    new_delegation = Delegation(
        id=str(uuid.uuid4()),
        delegator_id=user_id if delegator_type == 'user' else delegator_id,
        delegator_type=delegator_type,
        delegatee_id=data['delegatee_id'],
        delegatee_type='agent',
        scope=data['scope'],
        purpose=data.get('purpose', ''),
        delegated_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=data.get('expires_in', 1) / 3600),
        is_active=True
    )
    
    # Set constraints if provided
    if 'constraints' in data:
        new_delegation.set_constraints(data['constraints'])
    
    db.session.add(new_delegation)
    db.session.commit()
    
    # Generate delegation token
    delegation_chain = []
    
    # If delegator is an agent, get its delegation chain
    if delegator_type == 'agent':
        try:
            # Get the delegator's token to extract its delegation chain
            delegator_token = Token.query.filter_by(agent_id=delegator_id).first()
            if delegator_token and delegator_token.id_token:
                delegator_id_token = jwt.decode(delegator_token.id_token, options={"verify_signature": False})
                if 'delegation_chain' in delegator_id_token:
                    delegation_chain = delegator_id_token['delegation_chain']
        except Exception as e:
            # If there's an error, just start a new chain
            pass
    
    # Add current delegation step to chain
    delegation_chain.append({
        'iss': request.host_url,
        'sub': new_delegation.delegator_id,
        'aud': new_delegation.delegatee_id,
        'delegated_at': int(new_delegation.delegated_at.timestamp()),
        'scope': new_delegation.scope,
        'purpose': new_delegation.purpose,
        'constraints': new_delegation.get_constraints(),
        'jti': new_delegation.id
    })
    
    # Create ID token with delegation chain
    id_token_payload = {
        'iss': request.host_url,
        'sub': new_delegation.delegatee_id,
        'aud': 'client_id',  # In a real implementation, use the actual client ID
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        'iat': int(datetime.utcnow().timestamp()),
        'auth_time': int(datetime.utcnow().timestamp()),
        'agent_type': delegatee.agent_type,
        'agent_model': delegatee.agent_model,
        'agent_version': delegatee.agent_version,
        'agent_provider': delegatee.agent_provider,
        'agent_instance_id': delegatee.instance_id,
        'delegator_sub': new_delegation.delegator_id,
        'delegation_purpose': new_delegation.purpose,
        'agent_capabilities': delegatee.get_capabilities(),
        'agent_trust_level': delegatee.trust_level,
        'delegation_chain': delegation_chain
    }
    
    id_token = jwt.encode(id_token_payload, 'jwt-secret-key', algorithm='HS256')
    
    # Generate access token
    access_token_payload = {
        'sub': new_delegation.delegatee_id,
        'iat': int(datetime.utcnow().timestamp()),
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        'scope': new_delegation.scope,
        'delegator_sub': new_delegation.delegator_id
    }
    
    access_token = jwt.encode(access_token_payload, 'jwt-secret-key', algorithm='HS256')
    
    # Store tokens
    token_record = Token(
        id=str(uuid.uuid4()),
        token_type='id_token',
        access_token=access_token,
        id_token=id_token,
        client_id='default',
        user_id=user_id,
        agent_id=new_delegation.delegatee_id,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        scope=new_delegation.scope
    )
    
    db.session.add(token_record)
    db.session.commit()
    
    return jsonify({
        "delegation_id": new_delegation.id,
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,  # 1 hour in seconds
        "scope": new_delegation.scope
    }), 201

@delegation_bp.route('/<delegation_id>', methods=['GET'])
def get_delegation(delegation_id):
    """Get delegation details"""
    # Get user ID from token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode token to get user ID
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
        user_id = payload['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # Get delegation
    delegation = Delegation.query.filter_by(id=delegation_id).first()
    
    if not delegation:
        return jsonify({"error": "Delegation not found"}), 404
    
    # Check if user is involved in the delegation
    if delegation.delegator_id != user_id and delegation.delegatee.owner_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({
        "delegation": delegation.to_dict()
    }), 200

@delegation_bp.route('/<delegation_id>', methods=['DELETE'])
def revoke_delegation(delegation_id):
    """Revoke a delegation"""
    # Get user ID from token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode token to get user ID
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
        user_id = payload['sub']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # Get delegation
    delegation = Delegation.query.filter_by(id=delegation_id).first()
    
    if not delegation:
        return jsonify({"error": "Delegation not found"}), 404
    
    # Check if user is the delegator
    if delegation.delegator_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    # Revoke delegation
    delegation.is_active = False
    db.session.commit()
    
    # Revoke associated tokens
    tokens = Token.query.filter_by(agent_id=delegation.delegatee_id).all()
    for token in tokens:
        db.session.delete(token)
    
    db.session.commit()
    
    return jsonify({
        "message": "Delegation revoked successfully"
    }), 200

@delegation_bp.route('/chain', methods=['GET'])
def get_delegation_chain():
    """Get the delegation chain for the authenticated entity"""
    # Get token
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        # Decode token
        payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # If this is an agent token with a delegation chain
    if 'delegation_chain' in payload:
        return jsonify({
            "delegation_chain": payload['delegation_chain']
        }), 200
    
    # If this is a user token, return empty chain
    return jsonify({
        "delegation_chain": []
    }), 200
