-- MCP Auth Platform Database Schema

-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agents table
CREATE TABLE agents (
    id VARCHAR(36) PRIMARY KEY,
    instance_id VARCHAR(100) UNIQUE NOT NULL,
    agent_type VARCHAR(50) NOT NULL,
    agent_model VARCHAR(50) NOT NULL,
    agent_version VARCHAR(50),
    agent_provider VARCHAR(100) NOT NULL,
    trust_level VARCHAR(50) DEFAULT 'unverified',
    capabilities TEXT, -- JSON array of capabilities
    owner_id VARCHAR(36) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Attestations table
CREATE TABLE attestations (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) NOT NULL,
    format VARCHAR(100) NOT NULL,
    token TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    verification_timestamp TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

-- Delegations table
CREATE TABLE delegations (
    id VARCHAR(36) PRIMARY KEY,
    delegator_id VARCHAR(36) NOT NULL,
    delegator_type VARCHAR(10) NOT NULL, -- 'user' or 'agent'
    delegatee_id VARCHAR(36) NOT NULL,
    delegatee_type VARCHAR(10) NOT NULL, -- 'agent'
    scope TEXT NOT NULL, -- Space-separated OAuth scopes
    purpose VARCHAR(255),
    constraints TEXT, -- JSON object of constraints
    delegated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (delegatee_id) REFERENCES agents(id)
);

-- Clients table (OAuth clients)
CREATE TABLE clients (
    id VARCHAR(36) PRIMARY KEY,
    client_id VARCHAR(100) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(100) NOT NULL,
    redirect_uris TEXT NOT NULL, -- JSON array of URIs
    grant_types TEXT NOT NULL, -- JSON array of grant types
    response_types TEXT NOT NULL, -- JSON array of response types
    scope VARCHAR(255) NOT NULL,
    user_id VARCHAR(36),
    client_uri VARCHAR(255),
    logo_uri VARCHAR(255),
    tos_uri VARCHAR(255),
    policy_uri VARCHAR(255),
    jwks_uri VARCHAR(255),
    jwks TEXT,
    contacts TEXT, -- JSON array of contact emails
    
    -- Agent-specific metadata
    agent_provider VARCHAR(100),
    agent_models_supported TEXT, -- JSON array
    agent_capabilities TEXT, -- JSON array
    attestation_formats_supported TEXT, -- JSON array
    delegation_methods_supported TEXT, -- JSON array
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tokens table
CREATE TABLE tokens (
    id VARCHAR(36) PRIMARY KEY,
    token_type VARCHAR(40) NOT NULL, -- 'access_token', 'refresh_token', 'id_token'
    access_token VARCHAR(255) UNIQUE,
    refresh_token VARCHAR(255) UNIQUE,
    id_token TEXT,
    client_id VARCHAR(100) NOT NULL,
    user_id VARCHAR(36),
    agent_id VARCHAR(36),
    expires_at TIMESTAMP NOT NULL,
    scope TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

-- Create indexes for performance
CREATE INDEX idx_agents_owner_id ON agents(owner_id);
CREATE INDEX idx_attestations_agent_id ON attestations(agent_id);
CREATE INDEX idx_delegations_delegator_id ON delegations(delegator_id);
CREATE INDEX idx_delegations_delegatee_id ON delegations(delegatee_id);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_agent_id ON tokens(agent_id);
