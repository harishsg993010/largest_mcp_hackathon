from flask import Blueprint, request, jsonify
import jwt
from datetime import datetime, timedelta
import uuid
import json
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Token, Client

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/health', methods=['GET'])
@auth_bp.route('/health/', methods=['GET'])
def health_check():
    """Health check endpoint for testing API connectivity"""
    return jsonify({
        "status": "ok",
        "message": "Auth API is running",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already exists"}), 400
    
    # Create new user
    new_user = User(
        id=str(uuid.uuid4()),
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        first_name=data.get('first_name', ''),
        last_name=data.get('last_name', '')
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        "message": "User registered successfully",
        "user": new_user.to_dict()
    }), 201

@auth_bp.route('/login', methods=['POST'])
@auth_bp.route('/login/', methods=['POST'])  # Also handle with trailing slash
def login():
    """Authenticate a user and return tokens"""
    try:
        # Log request information
        print(f"Login attempt received. Method: {request.method}, Content-Type: {request.headers.get('Content-Type')}")
        
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
            print(f"Received JSON data: {data.keys() if data else 'None'}")
        else:
            data = request.form
            print(f"Received form data: {data.keys() if data else 'None'}")
        
        # If no data was parsed, try to get raw data
        if not data:
            print(f"No data parsed, raw data: {request.data}")
            try:
                data = json.loads(request.data)
            except:
                print("Could not parse raw data as JSON")
                data = {}
        
        # Validate required fields
        if not data.get('username') or not data.get('password'):
            print("Login failed: Missing username or password")
            return jsonify({"error": "Username and password are required"}), 400
        
        print(f"Login attempt for username: {data.get('username')}")
        
        # Find user
        user = User.query.filter_by(username=data['username']).first()
        
        if not user:
            print(f"Login failed: User not found - {data.get('username')}")
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Check password
        if not check_password_hash(user.password_hash, data['password']):
            print(f"Login failed: Invalid password for user {data.get('username')}")
            return jsonify({"error": "Invalid username or password"}), 401
        
        print(f"Login successful for user {data.get('username')}")
        
        # Generate tokens
        access_token = generate_token(user.id, 'access_token')
        refresh_token = generate_token(user.id, 'refresh_token')
        
        # Store tokens in database
        token = Token(
            id=str(uuid.uuid4()),
            token_type='access_token',
            access_token=access_token,
            refresh_token=refresh_token,
            client_id='default',  # For direct login, use default client
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry for access token
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Return successful response
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,  # 1 hour in seconds
            "user_id": user.id,
            "user": user.to_dict()
        }), 200
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """Refresh an access token using a refresh token"""
    data = request.get_json()
    
    if not data.get('refresh_token'):
        return jsonify({"error": "Refresh token is required"}), 400
    
    # Find token in database
    token = Token.query.filter_by(refresh_token=data['refresh_token']).first()
    
    if not token or token.is_expired():
        return jsonify({"error": "Invalid or expired refresh token"}), 401
    
    # Generate new access token
    new_access_token = generate_token(token.user_id, 'access_token')
    
    # Update token in database
    token.access_token = new_access_token
    token.expires_at = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    return jsonify({
        "access_token": new_access_token,
        "token_type": "Bearer",
        "expires_in": 3600  # 1 hour in seconds
    }), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Invalidate tokens"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header is required"}), 401
    
    access_token = auth_header.split(' ')[1]
    
    # Find and delete token
    token = Token.query.filter_by(access_token=access_token).first()
    
    if token:
        db.session.delete(token)
        db.session.commit()
    
    return jsonify({"message": "Logged out successfully"}), 200

@auth_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """OAuth 2.0 authorization endpoint"""
    if request.method == 'GET':
        # Validate request parameters
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        scope = request.args.get('scope')
        state = request.args.get('state')
        
        if not client_id or not redirect_uri or not response_type:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Verify client
        client = Client.query.filter_by(client_id=client_id).first()
        
        if not client:
            return jsonify({"error": "Invalid client"}), 400
        
        # Verify redirect URI
        if redirect_uri not in client.get_redirect_uris():
            return jsonify({"error": "Invalid redirect URI"}), 400
        
        # Verify response type
        if response_type not in client.get_response_types():
            return jsonify({"error": "Unsupported response type"}), 400
        
        # Store request parameters in session for POST handling
        # In a real implementation, you'd use Flask session
        
        # Return authorization form (in a real app, render a template)
        return jsonify({
            "client_name": client.client_name,
            "scope": scope,
            "state": state
        }), 200
    
    elif request.method == 'POST':
        # Process authorization form submission
        data = request.get_json()
        
        # Validate user credentials and consent
        # In a real implementation, verify user is logged in and has consented
        
        # Generate authorization code or tokens based on response_type
        # Redirect user back to client with code/tokens
        
        # For demo purposes, return a mock response
        return jsonify({
            "code": "authorization_code_123",
            "state": data.get('state')
        }), 200

@auth_bp.route('/token', methods=['POST'])
def token():
    """OAuth 2.0 token endpoint"""
    # Get request data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    grant_type = data.get('grant_type')
    
    if not grant_type:
        return jsonify({"error": "grant_type is required"}), 400
    
    # Handle different grant types
    if grant_type == 'authorization_code':
        # Exchange authorization code for tokens
        code = data.get('code')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        redirect_uri = data.get('redirect_uri')
        
        if not code or not client_id or not redirect_uri:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Verify client
        client = Client.query.filter_by(client_id=client_id).first()
        
        if not client or client.client_secret != client_secret:
            return jsonify({"error": "Invalid client credentials"}), 401
        
        # Verify authorization code
        # In a real implementation, validate the code from database
        
        # Generate tokens
        # For demo purposes, return mock tokens
        return jsonify({
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "id_token": "mock_id_token"
        }), 200
    
    elif grant_type == 'refresh_token':
        # Refresh access token
        refresh_token = data.get('refresh_token')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not refresh_token or not client_id:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Verify client
        client = Client.query.filter_by(client_id=client_id).first()
        
        if not client or client.client_secret != client_secret:
            return jsonify({"error": "Invalid client credentials"}), 401
        
        # Verify refresh token
        # In a real implementation, validate the refresh token from database
        
        # Generate new access token
        # For demo purposes, return mock token
        return jsonify({
            "access_token": "new_mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }), 200
    
    elif grant_type == 'client_credentials':
        # Client credentials flow
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        scope = data.get('scope')
        
        if not client_id or not client_secret:
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Verify client
        client = Client.query.filter_by(client_id=client_id).first()
        
        if not client or client.client_secret != client_secret:
            return jsonify({"error": "Invalid client credentials"}), 401
        
        # Generate tokens
        # For demo purposes, return mock token
        return jsonify({
            "access_token": "client_credentials_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }), 200
    
    else:
        return jsonify({"error": "Unsupported grant type"}), 400

def generate_token(user_id, token_type):
    """Generate JWT token"""
    payload = {
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1) if token_type == 'access_token' else datetime.utcnow() + timedelta(days=30),
        'type': token_type
    }
    
    return jwt.encode(payload, 'jwt-secret-key', algorithm='HS256')
