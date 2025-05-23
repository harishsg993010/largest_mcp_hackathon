import os
from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from dotenv import load_dotenv
from config import config
from models import db, migrate
# Temporarily disable custom middleware
# from middleware import cors_middleware
from routes.auth import auth_bp
from routes.users import users_bp
from routes.agents import agents_bp
from routes.attestation import attestation_bp
from routes.delegation import delegation_bp
from routes.discovery import discovery_bp

# Load environment variables
load_dotenv()

def create_app(config_name='development'):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Simple CORS setup - allow all origins and methods
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    
    # Configure URL handling
    app.url_map.strict_slashes = False
    
    # Add CORS headers to all responses
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    
    # Register blueprints - ensure trailing slashes are consistent
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(agents_bp, url_prefix='/api/agents')
    app.register_blueprint(attestation_bp, url_prefix='/api/attestation')
    app.register_blueprint(delegation_bp, url_prefix='/api/delegation')
    app.register_blueprint(discovery_bp, url_prefix='/.well-known')
    
    # Add route for handling OPTIONS requests at the root level
    @app.route('/api/<path:path>', methods=['OPTIONS'])
    @app.route('/api/', methods=['OPTIONS'])
    @app.route('/api', methods=['OPTIONS'])
    def handle_options(path=None):
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Max-Age', '86400')  # 24 hours
        return response, 200
    
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({"status": "healthy"})
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found"}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({"error": "Internal server error"}), 500
    
    return app

if __name__ == '__main__':
    app = create_app(os.getenv('FLASK_ENV', 'development'))
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
