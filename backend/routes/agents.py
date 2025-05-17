from flask import Blueprint, request, jsonify
import jwt
from datetime import datetime, timedelta
import uuid
import json
from models import db, Agent, User, Attestation, Delegation, Token

agents_bp = Blueprint('agents', __name__)

@agents_bp.route('/', methods=['GET'])
@agents_bp.route('', methods=['GET'])  # Also handle without trailing slash
def get_agents():
    """Get all agents for the authenticated user"""
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
    
    # Get agents for user
    agents = Agent.query.filter_by(owner_id=user_id).all()
    
    return jsonify({
        "agents": [agent.to_dict() for agent in agents]
    }), 200

@agents_bp.route('/', methods=['POST'])
def register_agent():
    """Register a new agent"""
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
    
    # Validate request data
    data = request.get_json()
    
    required_fields = ['instance_id', 'agent_type', 'agent_model', 'agent_provider']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Check if agent already exists
    existing_agent = Agent.query.filter_by(instance_id=data['instance_id']).first()
    if existing_agent:
        return jsonify({"error": "Agent with this instance ID already exists"}), 400
    
    # Create new agent
    new_agent = Agent(
        id=str(uuid.uuid4()),
        instance_id=data['instance_id'],
        agent_type=data['agent_type'],
        agent_model=data['agent_model'],
        agent_version=data.get('agent_version'),
        agent_provider=data['agent_provider'],
        trust_level=data.get('trust_level', 'unverified'),
        owner_id=user_id
    )
    
    # Set capabilities if provided
    if 'capabilities' in data:
        new_agent.set_capabilities(data['capabilities'])
    
    db.session.add(new_agent)
    db.session.commit()
    
    # If attestation is provided, create attestation record
    if 'attestation' in data:
        attestation = Attestation(
            id=str(uuid.uuid4()),
            agent_id=new_agent.id,
            format=data['attestation'].get('format', 'unknown'),
            token=data['attestation'].get('token', ''),
            timestamp=datetime.utcnow(),
            verified=False
        )
        
        db.session.add(attestation)
        db.session.commit()
    
    return jsonify({
        "message": "Agent registered successfully",
        "agent": new_agent.to_dict()
    }), 201

@agents_bp.route('/<agent_id>', methods=['GET'])
@agents_bp.route('/<agent_id>/', methods=['GET'])  # Also handle with trailing slash
def get_agent_by_id(agent_id):
    """Get agent by ID"""
    print(f"Getting agent by ID: {agent_id}")
    
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
                print(f"Agent is accessing its own data, authorized")
                # Continue to return agent data
            else:
                print(f"Agent {requester_id} is not authorized to access agent {agent_id}")
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
    
    # Get agent
    agent = Agent.query.filter_by(id=agent_id).first()
    
    if not agent:
        print(f"Agent not found: {agent_id}")
        return jsonify({"error": "Agent not found"}), 404
    
    return jsonify({
        "agent": agent.to_dict()
    }), 200

@agents_bp.route('/<agent_id>', methods=['PUT'])
def update_agent(agent_id):
    """Update agent details"""
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
    
    # Get agent
    agent = Agent.query.filter_by(id=agent_id).first()
    
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    
    # Check if user owns the agent
    if agent.owner_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    # Update agent
    data = request.get_json()
    
    # Update fields
    if 'agent_type' in data:
        agent.agent_type = data['agent_type']
    
    if 'agent_model' in data:
        agent.agent_model = data['agent_model']
    
    if 'agent_version' in data:
        agent.agent_version = data['agent_version']
    
    if 'agent_provider' in data:
        agent.agent_provider = data['agent_provider']
    
    if 'trust_level' in data:
        agent.trust_level = data['trust_level']
    
    if 'capabilities' in data:
        agent.set_capabilities(data['capabilities'])
    
    if 'is_active' in data:
        agent.is_active = data['is_active']
    
    agent.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        "message": "Agent updated successfully",
        "agent": agent.to_dict()
    }), 200

@agents_bp.route('/<agent_id>', methods=['DELETE'])
def delete_agent(agent_id):
    """Delete an agent"""
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
    
    # Get agent
    agent = Agent.query.filter_by(id=agent_id).first()
    
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    
    # Check if user owns the agent
    if agent.owner_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    # Delete agent
    db.session.delete(agent)
    db.session.commit()
    
    return jsonify({
        "message": "Agent deleted successfully"
    }), 200

@agents_bp.route('/<agent_id>/token', methods=['POST'])
@agents_bp.route('/<agent_id>/token/', methods=['POST'])  # Also handle with trailing slash
def generate_agent_token(agent_id):
    """Generate a token for an agent"""
    try:
        print(f"Token generation requested for agent: {agent_id}")
        print(f"Request method: {request.method}, Content-Type: {request.headers.get('Content-Type')}")
        
        # Get user ID from token
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            print("Token generation failed: Missing or invalid Authorization header")
            return jsonify({"error": "Authorization header is required"}), 401
        
        token = auth_header.split(' ')[1]
        print(f"Token provided: {token[:10]}...")
        
        try:
            # Decode token to get user ID
            payload = jwt.decode(token, 'jwt-secret-key', algorithms=['HS256'])
            user_id = payload['sub']
            print(f"Token decoded successfully, user_id: {user_id}")
        except jwt.ExpiredSignatureError:
            print("Token generation failed: Token expired")
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            print(f"Token generation failed: Invalid token - {str(e)}")
            return jsonify({"error": "Invalid token"}), 401
        
        # Get agent
        agent = Agent.query.filter_by(id=agent_id).first()
        
        if not agent:
            print(f"Token generation failed: Agent not found - {agent_id}")
            return jsonify({"error": "Agent not found"}), 404
        
        # Check if user owns the agent
        if agent.owner_id != user_id:
            print(f"Token generation failed: Unauthorized - User {user_id} does not own agent {agent_id}")
            return jsonify({"error": "Unauthorized"}), 403
        
        # Parse request data
        if request.is_json:
            data = request.get_json()
            print(f"Received JSON data: {data}")
        else:
            data = request.form
            print(f"Received form data: {data}")
        
        # If no data was parsed, try to get raw data
        if not data:
            print(f"No data parsed, raw data: {request.data}")
            try:
                data = json.loads(request.data)
            except:
                print("Could not parse raw data as JSON")
                data = {}
        
        scope = data.get('scope', [])
        purpose = data.get('purpose', '')
        constraints = data.get('constraints', {})
        
        print(f"Token parameters - scope: {scope}, purpose: {purpose}")
        
        # Convert scope to list if it's a string
        if isinstance(scope, str):
            scope = [scope]
        
        # Ensure scope is a list
        if not isinstance(scope, list):
            scope = []
    
        # Generate agent token
        # This is a simplified version - in a real implementation, you'd create a proper ID token with agent claims
        payload = {
            'sub': agent.id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1),
            'agent_type': agent.agent_type,
            'agent_model': agent.agent_model,
            'agent_version': agent.agent_version,
            'agent_provider': agent.agent_provider,
            'agent_instance_id': agent.instance_id,
            'delegator_sub': user_id,
            'delegation_purpose': purpose,
            'agent_capabilities': agent.get_capabilities(),
            'agent_trust_level': agent.trust_level
        }
        
        # Add OIDC-A specific claims
        if hasattr(agent, 'get_attestations'):
            attestations = agent.get_attestations()
            payload['agent_attestations'] = attestations
        
        print(f"Generated token payload: {payload}")
        
        # Generate the token
        try:
            agent_token = jwt.encode(payload, 'jwt-secret-key', algorithm='HS256')
            print(f"Token encoded successfully: {agent_token[:10]}...")
        except Exception as e:
            print(f"Error encoding token: {str(e)}")
            return jsonify({"error": f"Error generating token: {str(e)}"}), 500
        
        # Create delegation record
        try:
            delegation_id = str(uuid.uuid4())
            
            # Convert scope list to string for SQLite compatibility
            scope_str = ' '.join(scope) if scope else ''
            print(f"Converting scope from {scope} to string: '{scope_str}'")
            
            delegation = Delegation(
                id=delegation_id,
                delegator_id=user_id,
                delegator_type='user',
                delegatee_id=agent.id,
                delegatee_type='agent',
                scope=scope_str,
                purpose=purpose,
                delegated_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=1),
                is_active=True
            )
            
            if constraints:
                delegation.set_constraints(constraints)
            
            db.session.add(delegation)
            print(f"Delegation record created: {delegation_id}")
        except Exception as e:
            print(f"Error creating delegation: {str(e)}")
            return jsonify({"error": f"Error creating delegation: {str(e)}"}), 500
        
        # Store token in database
        try:
            token_id = str(uuid.uuid4())
            token_record = Token(
                id=token_id,
                token_type='access_token',
                access_token=agent_token,
                client_id='default',
                user_id=user_id,
                agent_id=agent.id,
                expires_at=datetime.utcnow() + timedelta(hours=1),
                scope=scope_str  # Use the same scope string we created for delegation
            )
            
            db.session.add(token_record)
            print(f"Token record created: {token_id}")
        except Exception as e:
            print(f"Error creating token record: {str(e)}")
            return jsonify({"error": f"Error storing token: {str(e)}"}), 500
        
        # Commit all changes to the database
        try:
            db.session.commit()
            print("Database changes committed successfully")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing to database: {str(e)}")
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        
        # Create response
        response = {
            "access_token": agent_token,
            "token_type": "Bearer",
            "expires_in": 3600,  # 1 hour in seconds
            "scope": scope_str,
            "delegation_id": delegation_id
        }
        
        print(f"Returning successful response with token")
        return jsonify(response), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Unexpected error in token generation: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
