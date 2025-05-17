"""
Authentication client for the MCP Auth SDK.
"""

import os
import time
import json
import requests
import jwt
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urljoin

from .exceptions import (
    AuthenticationError, 
    AuthorizationError, 
    APIError, 
    ValidationError
)


class AuthClient:
    """
    Client for authenticating with the MCP Auth Platform.
    
    This client handles user authentication, token management, and
    OpenID Connect discovery.
    """
    
    def __init__(
        self, 
        auth_server_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        token_storage: Optional[Dict] = None
    ):
        """
        Initialize the AuthClient.
        
        Args:
            auth_server_url: Base URL of the MCP Auth Platform
            client_id: OAuth client ID (optional)
            client_secret: OAuth client secret (optional)
            redirect_uri: OAuth redirect URI (optional)
            token_storage: Dictionary to store tokens (optional)
        """
        self.auth_server_url = auth_server_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.token_storage = token_storage or {}
        
        # OpenID Connect configuration
        self.openid_config = None
        
        # Session for making HTTP requests
        self.session = requests.Session()
    
    def discover_openid_configuration(self) -> Dict:
        """
        Discover OpenID Connect configuration from the auth server.
        
        Returns:
            Dict: OpenID Connect configuration
        """
        try:
            response = self.session.get(
                f"{self.auth_server_url}/.well-known/openid-configuration"
            )
            response.raise_for_status()
            self.openid_config = response.json()
            return self.openid_config
        except requests.RequestException as e:
            raise APIError(f"Failed to discover OpenID configuration: {str(e)}", 
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def get_openid_configuration(self) -> Dict:
        """
        Get the OpenID Connect configuration, discovering it if not already loaded.
        
        Returns:
            Dict: OpenID Connect configuration
        """
        if not self.openid_config:
            return self.discover_openid_configuration()
        return self.openid_config
    
    def get_authorization_url(
        self,
        scope: str = "openid profile",
        response_type: str = "code",
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Get the authorization URL for redirecting the user.
        
        Args:
            scope: OAuth scopes (space-separated)
            response_type: OAuth response type
            state: OAuth state parameter
            nonce: OpenID Connect nonce
            **kwargs: Additional parameters to include in the URL
            
        Returns:
            str: Authorization URL
        """
        if not self.client_id:
            raise ValidationError("client_id is required for authorization")
        
        if not self.redirect_uri:
            raise ValidationError("redirect_uri is required for authorization")
        
        config = self.get_openid_configuration()
        authorization_endpoint = config.get('authorization_endpoint')
        
        if not authorization_endpoint:
            raise AuthenticationError("Authorization endpoint not found in OpenID configuration")
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': response_type,
            'scope': scope
        }
        
        if state:
            params['state'] = state
        
        if nonce:
            params['nonce'] = nonce
        
        # Add any additional parameters
        params.update(kwargs)
        
        # Build the URL
        url = authorization_endpoint
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        
        return f"{url}?{query_string}"
    
    def exchange_code_for_tokens(self, code: str) -> Dict:
        """
        Exchange an authorization code for tokens.
        
        Args:
            code: Authorization code from the redirect
            
        Returns:
            Dict: Token response containing access_token, id_token, etc.
        """
        if not self.client_id:
            raise ValidationError("client_id is required for token exchange")
        
        if not self.redirect_uri:
            raise ValidationError("redirect_uri is required for token exchange")
        
        config = self.get_openid_configuration()
        token_endpoint = config.get('token_endpoint')
        
        if not token_endpoint:
            raise AuthenticationError("Token endpoint not found in OpenID configuration")
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri
        }
        
        # Add client secret if available
        if self.client_secret:
            data['client_secret'] = self.client_secret
        
        try:
            response = self.session.post(token_endpoint, data=data)
            response.raise_for_status()
            tokens = response.json()
            
            # Store tokens
            self.token_storage.update(tokens)
            
            return tokens
        except requests.RequestException as e:
            raise APIError(f"Failed to exchange code for tokens: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def login_with_password(self, username: str, password: str) -> Dict:
        """
        Login with username and password.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            Dict: Token response containing access_token, refresh_token, etc.
        """
        try:
            response = self.session.post(
                f"{self.auth_server_url}/api/auth/login",
                json={'username': username, 'password': password}
            )
            response.raise_for_status()
            tokens = response.json()
            
            # Store tokens
            self.token_storage.update(tokens)
            
            return tokens
        except requests.RequestException as e:
            raise APIError(f"Login failed: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def refresh_token(self, refresh_token: Optional[str] = None) -> Dict:
        """
        Refresh the access token using a refresh token.
        
        Args:
            refresh_token: Refresh token to use (if not provided, uses stored token)
            
        Returns:
            Dict: Token response containing new access_token, etc.
        """
        refresh_token = refresh_token or self.token_storage.get('refresh_token')
        
        if not refresh_token:
            raise AuthenticationError("No refresh token available")
        
        config = self.get_openid_configuration()
        token_endpoint = config.get('token_endpoint')
        
        if not token_endpoint:
            # Fall back to direct endpoint
            token_endpoint = f"{self.auth_server_url}/api/auth/refresh"
        
        try:
            response = self.session.post(
                token_endpoint,
                json={'refresh_token': refresh_token}
            )
            response.raise_for_status()
            tokens = response.json()
            
            # Update stored tokens
            self.token_storage.update(tokens)
            
            return tokens
        except requests.RequestException as e:
            raise APIError(f"Token refresh failed: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def logout(self) -> bool:
        """
        Logout the current user by invalidating tokens.
        
        Returns:
            bool: True if logout was successful
        """
        access_token = self.token_storage.get('access_token')
        
        if not access_token:
            return True  # Already logged out
        
        try:
            response = self.session.post(
                f"{self.auth_server_url}/api/auth/logout",
                headers={'Authorization': f"Bearer {access_token}"}
            )
            response.raise_for_status()
            
            # Clear stored tokens
            self.token_storage.clear()
            
            return True
        except requests.RequestException as e:
            raise APIError(f"Logout failed: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def get_user_info(self) -> Dict:
        """
        Get information about the authenticated user.
        
        Returns:
            Dict: User information
        """
        access_token = self.token_storage.get('access_token')
        
        if not access_token:
            raise AuthenticationError("Not authenticated")
        
        config = self.get_openid_configuration()
        userinfo_endpoint = config.get('userinfo_endpoint')
        
        if not userinfo_endpoint:
            # Fall back to direct endpoint
            userinfo_endpoint = f"{self.auth_server_url}/api/users/me"
        
        try:
            response = self.session.get(
                userinfo_endpoint,
                headers={'Authorization': f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise APIError(f"Failed to get user info: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def validate_id_token(self, id_token: Optional[str] = None) -> Dict:
        """
        Validate an ID token and return its claims.
        
        Args:
            id_token: ID token to validate (if not provided, uses stored token)
            
        Returns:
            Dict: ID token claims
        """
        id_token = id_token or self.token_storage.get('id_token')
        
        if not id_token:
            raise AuthenticationError("No ID token available")
        
        try:
            # In a production environment, you would verify the signature
            # using the JWKS from the auth server
            claims = jwt.decode(id_token, options={"verify_signature": False})
            
            # Validate expiration
            if 'exp' in claims and claims['exp'] < time.time():
                raise AuthenticationError("ID token has expired")
            
            return claims
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Invalid ID token: {str(e)}")
    
    def introspect_token(self, token: str, token_type_hint: str = 'access_token') -> Dict:
        """
        Introspect a token to check its validity and get information about it.
        
        Args:
            token: Token to introspect
            token_type_hint: Type of token ('access_token', 'refresh_token', etc.)
            
        Returns:
            Dict: Token introspection result
        """
        config = self.get_openid_configuration()
        introspection_endpoint = config.get('introspection_endpoint')
        
        if not introspection_endpoint:
            raise AuthenticationError("Introspection endpoint not found in OpenID configuration")
        
        try:
            response = self.session.post(
                introspection_endpoint,
                data={'token': token, 'token_type_hint': token_type_hint}
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise APIError(f"Token introspection failed: {str(e)}",
                          getattr(e.response, 'status_code', None),
                          getattr(e, 'response', None))
    
    def is_authenticated(self) -> bool:
        """
        Check if the client is authenticated with a valid access token.
        
        Returns:
            bool: True if authenticated with a valid token
        """
        access_token = self.token_storage.get('access_token')
        
        if not access_token:
            return False
        
        try:
            # Decode the token to check expiration
            # In a production environment, you would verify the signature
            claims = jwt.decode(
                access_token, 
                options={"verify_signature": False}
            )
            
            # Check if token is expired
            if 'exp' in claims and claims['exp'] < time.time():
                return False
            
            return True
        except jwt.PyJWTError:
            return False
    
    def get_access_token(self) -> str:
        """
        Get the current access token, refreshing if necessary.
        
        Returns:
            str: Access token
        """
        if not self.is_authenticated() and 'refresh_token' in self.token_storage:
            # Token is expired or invalid, but we have a refresh token
            self.refresh_token()
        
        access_token = self.token_storage.get('access_token')
        
        if not access_token:
            raise AuthenticationError("Not authenticated")
        
        return access_token
    
    def request(
        self, 
        method: str, 
        endpoint: str, 
        authenticated: bool = True,
        **kwargs
    ) -> requests.Response:
        """
        Make an HTTP request to the auth server.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to auth_server_url)
            authenticated: Whether to include the access token
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            Response: HTTP response
        """
        url = urljoin(self.auth_server_url, endpoint)
        
        if authenticated:
            # Get the access token
            access_token = self.get_access_token()
            
            # Add Authorization header
            headers = kwargs.get('headers', {})
            headers['Authorization'] = f"Bearer {access_token}"
            kwargs['headers'] = headers
        
        # Make the request
        response = self.session.request(method, url, **kwargs)
        
        try:
            response.raise_for_status()
        except requests.RequestException as e:
            raise APIError(
                f"Request failed: {str(e)}",
                getattr(e.response, 'status_code', None),
                getattr(e, 'response', None)
            )
        
        return response
