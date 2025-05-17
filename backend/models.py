from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import uuid
import json

db = SQLAlchemy()
migrate = Migrate()

class User(db.Model):
    """User model representing human users of the system"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    agents = db.relationship('Agent', back_populates='owner')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Agent(db.Model):
    """Agent model representing AI agents in the system"""
    __tablename__ = 'agents'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    instance_id = db.Column(db.String(100), unique=True, nullable=False)
    agent_type = db.Column(db.String(50), nullable=False)
    agent_model = db.Column(db.String(50), nullable=False)
    agent_version = db.Column(db.String(50))
    agent_provider = db.Column(db.String(100), nullable=False)
    trust_level = db.Column(db.String(50), default='unverified')
    capabilities = db.Column(db.Text)  # JSON array of capabilities
    owner_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = db.relationship('User', back_populates='agents')
    attestations = db.relationship('Attestation', back_populates='agent')
    delegations_received = db.relationship('Delegation', foreign_keys='Delegation.delegatee_id', back_populates='delegatee')
    
    def get_capabilities(self):
        if self.capabilities:
            return json.loads(self.capabilities)
        return []
    
    def set_capabilities(self, capabilities_list):
        self.capabilities = json.dumps(capabilities_list)
    
    def to_dict(self):
        return {
            'id': self.id,
            'instance_id': self.instance_id,
            'agent_type': self.agent_type,
            'agent_model': self.agent_model,
            'agent_version': self.agent_version,
            'agent_provider': self.agent_provider,
            'trust_level': self.trust_level,
            'capabilities': self.get_capabilities(),
            'owner_id': self.owner_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Attestation(db.Model):
    """Attestation model for verifying agent identity and integrity"""
    __tablename__ = 'attestations'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    format = db.Column(db.String(100), nullable=False)  # Format of attestation (e.g., TPM2-Quote)
    token = db.Column(db.Text, nullable=False)  # Attestation token or evidence
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # When the attestation was created
    verified = db.Column(db.Boolean, default=False)  # Whether the attestation has been verified
    verification_timestamp = db.Column(db.DateTime, nullable=True)  # When the attestation was verified
    
    agent = db.relationship('Agent', back_populates='attestations')
    
    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'format': self.format,
            'token': self.token,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'verified': self.verified,
            'verification_timestamp': self.verification_timestamp.isoformat() if self.verification_timestamp else None
        }

class Delegation(db.Model):
    """Delegation model representing authority delegation between entities"""
    __tablename__ = 'delegations'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    delegator_id = db.Column(db.String(36), nullable=False)
    delegator_type = db.Column(db.String(10), nullable=False)  # 'user' or 'agent'
    delegatee_id = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    delegatee_type = db.Column(db.String(10), nullable=False)  # 'agent'
    scope = db.Column(db.Text, nullable=False)  # Space-separated OAuth scopes
    purpose = db.Column(db.String(255))
    constraints = db.Column(db.Text)  # JSON object of constraints
    delegated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    delegatee = db.relationship('Agent', foreign_keys=[delegatee_id], back_populates='delegations_received')
    
    def get_constraints(self):
        if self.constraints:
            return json.loads(self.constraints)
        return {}
    
    def set_constraints(self, constraints_dict):
        self.constraints = json.dumps(constraints_dict)
    
    def to_dict(self):
        return {
            'id': self.id,
            'delegator_id': self.delegator_id,
            'delegator_type': self.delegator_type,
            'delegatee_id': self.delegatee_id,
            'delegatee_type': self.delegatee_type,
            'scope': self.scope,
            'purpose': self.purpose,
            'constraints': self.get_constraints(),
            'delegated_at': self.delegated_at.isoformat() if self.delegated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }

class Client(db.Model):
    """OAuth Client model"""
    __tablename__ = 'clients'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id = db.Column(db.String(100), unique=True, nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    client_name = db.Column(db.String(100), nullable=False)
    redirect_uris = db.Column(db.Text, nullable=False)  # JSON array of URIs
    grant_types = db.Column(db.Text, nullable=False)  # JSON array of grant types
    response_types = db.Column(db.Text, nullable=False)  # JSON array of response types
    scope = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    client_uri = db.Column(db.String(255))
    logo_uri = db.Column(db.String(255))
    tos_uri = db.Column(db.String(255))
    policy_uri = db.Column(db.String(255))
    jwks_uri = db.Column(db.String(255))
    jwks = db.Column(db.Text)
    contacts = db.Column(db.Text)  # JSON array of contact emails
    
    # Agent-specific metadata
    agent_provider = db.Column(db.String(100))
    agent_models_supported = db.Column(db.Text)  # JSON array
    agent_capabilities = db.Column(db.Text)  # JSON array
    attestation_formats_supported = db.Column(db.Text)  # JSON array
    delegation_methods_supported = db.Column(db.Text)  # JSON array
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def get_redirect_uris(self):
        if self.redirect_uris:
            return json.loads(self.redirect_uris)
        return []
    
    def set_redirect_uris(self, uris_list):
        self.redirect_uris = json.dumps(uris_list)
    
    def get_grant_types(self):
        if self.grant_types:
            return json.loads(self.grant_types)
        return []
    
    def set_grant_types(self, grant_types_list):
        self.grant_types = json.dumps(grant_types_list)
    
    def get_response_types(self):
        if self.response_types:
            return json.loads(self.response_types)
        return []
    
    def set_response_types(self, response_types_list):
        self.response_types = json.dumps(response_types_list)
    
    def get_agent_models_supported(self):
        if self.agent_models_supported:
            return json.loads(self.agent_models_supported)
        return []
    
    def set_agent_models_supported(self, models_list):
        self.agent_models_supported = json.dumps(models_list)
    
    def get_agent_capabilities(self):
        if self.agent_capabilities:
            return json.loads(self.agent_capabilities)
        return []
    
    def set_agent_capabilities(self, capabilities_list):
        self.agent_capabilities = json.dumps(capabilities_list)
    
    def get_attestation_formats_supported(self):
        if self.attestation_formats_supported:
            return json.loads(self.attestation_formats_supported)
        return []
    
    def set_attestation_formats_supported(self, formats_list):
        self.attestation_formats_supported = json.dumps(formats_list)
    
    def get_delegation_methods_supported(self):
        if self.delegation_methods_supported:
            return json.loads(self.delegation_methods_supported)
        return []
    
    def set_delegation_methods_supported(self, methods_list):
        self.delegation_methods_supported = json.dumps(methods_list)
    
    def to_dict(self):
        return {
            'id': self.id,
            'client_id': self.client_id,
            'client_name': self.client_name,
            'redirect_uris': self.get_redirect_uris(),
            'grant_types': self.get_grant_types(),
            'response_types': self.get_response_types(),
            'scope': self.scope,
            'user_id': self.user_id,
            'client_uri': self.client_uri,
            'logo_uri': self.logo_uri,
            'tos_uri': self.tos_uri,
            'policy_uri': self.policy_uri,
            'jwks_uri': self.jwks_uri,
            'contacts': json.loads(self.contacts) if self.contacts else [],
            'agent_provider': self.agent_provider,
            'agent_models_supported': self.get_agent_models_supported(),
            'agent_capabilities': self.get_agent_capabilities(),
            'attestation_formats_supported': self.get_attestation_formats_supported(),
            'delegation_methods_supported': self.get_delegation_methods_supported(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Token(db.Model):
    """Token model for OAuth tokens"""
    __tablename__ = 'tokens'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_type = db.Column(db.String(40), nullable=False)  # 'access_token', 'refresh_token', 'id_token'
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    id_token = db.Column(db.Text)
    client_id = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    agent_id = db.Column(db.String(36), db.ForeignKey('agents.id'))
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at if self.expires_at else True
