# MCP Auth Platform

An Okta-like authentication and authorization system for MCP servers that implements OpenID Connect for Agents (OIDC-A) 1.0 specification.

OIDC-A : https://subramanya.ai/2025/04/28/oidc-a-proposal/

## Components

1. **Backend Service** - Python-based authentication and authorization service
2.  **SDK** - Python client library for MCP server integration

## Getting Started

### Prerequisites

- Python 3.9+
- SQL Database (PostgreSQL/MySQL)
- pip

### Installation

```bash
# Clone the repository
git clone <repository-url>

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies for the backend
cd backend
pip install -r requirements.txt

# Install dependencies for the SDK
cd ../sdk
pip install -r requirements.txt
```

### Running the Services

```bash
# Start the backend service
cd backend
python app.py

```

## Project Structure

- `/backend` - Python-based authentication and authorization service
- `/sdk` - Python client library for MCP server integration
- `/docs` - Documentation
- `/sql` - SQL database scripts and schemas

## Features

- User authentication and authorization
- Agent authentication and authorization (OIDC-A 1.0)
- Agent identity claims and verification
- Delegation chains and authority management
- Agent attestation and capability discovery
- Role-based access control
- Multi-factor authentication
- OAuth 2.0 and OpenID Connect support
- API token management
- User provisioning and deprovisioning
- Audit logging
