"""
Middleware for the MCP Auth Platform.
This module provides middleware functions for the Flask application.
"""

from functools import wraps
from flask import request, jsonify, make_response

def cors_middleware(app):
    """
    Middleware to handle CORS requests properly.
    """
    @app.after_request
    def after_request(response):
        # Allow requests from any origin
        response.headers.add('Access-Control-Allow-Origin', '*')
        
        # Allow specific headers
        response.headers.add('Access-Control-Allow-Headers', 
                            'Content-Type, Authorization, X-Requested-With')
        
        # Allow specific methods
        response.headers.add('Access-Control-Allow-Methods', 
                            'GET, POST, PUT, DELETE, OPTIONS')
        
        # Allow credentials
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        
        return response
    
    @app.before_request
    def handle_options():
        """Handle OPTIONS requests for CORS preflight"""
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 
                                'Content-Type, Authorization, X-Requested-With')
            response.headers.add('Access-Control-Allow-Methods', 
                                'GET, POST, PUT, DELETE, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
    
    return app
