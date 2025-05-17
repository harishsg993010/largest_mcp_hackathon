from flask import Blueprint, request, jsonify
import jwt
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Agent, Delegation

users_bp = Blueprint('users', __name__)

@users_bp.route('/me', methods=['GET'])
def get_current_user():
    """Get the authenticated user's profile"""
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
    
    # Get user
    user = User.query.filter_by(id=user_id).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "user": user.to_dict()
    }), 200

@users_bp.route('/me', methods=['PUT'])
def update_current_user():
    """Update the authenticated user's profile"""
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
    
    # Get user
    user = User.query.filter_by(id=user_id).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Update user
    data = request.get_json()
    
    if 'email' in data:
        # Check if email is already taken
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({"error": "Email already exists"}), 400
        user.email = data['email']
    
    if 'first_name' in data:
        user.first_name = data['first_name']
    
    if 'last_name' in data:
        user.last_name = data['last_name']
    
    if 'password' in data:
        user.password_hash = generate_password_hash(data['password'])
    
    user.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        "message": "User updated successfully",
        "user": user.to_dict()
    }), 200

@users_bp.route('/me/agents', methods=['GET'])
def get_user_agents():
    """Get all agents owned by the authenticated user"""
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
    
    # Get agents
    agents = Agent.query.filter_by(owner_id=user_id).all()
    
    return jsonify({
        "agents": [agent.to_dict() for agent in agents]
    }), 200

@users_bp.route('/me/delegations', methods=['GET'])
def get_user_delegations():
    """Get all delegations created by the authenticated user"""
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
    
    # Get delegations
    delegations = Delegation.query.filter_by(delegator_id=user_id, delegator_type='user').all()
    
    return jsonify({
        "delegations": [delegation.to_dict() for delegation in delegations]
    }), 200
