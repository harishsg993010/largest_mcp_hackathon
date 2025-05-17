"""
Setup script for MCP Auth Platform.
This script initializes the database and creates necessary tables.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

# Add the backend directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Import the models and app
from models import db, User, Agent, Attestation, Delegation, Client, Token
from app import create_app

def setup_database():
    """Set up the database and create tables."""
    print("Setting up database...")
    
    # Create a development app
    app = create_app('development')
    
    with app.app_context():
        # Create database if it doesn't exist
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
        if not database_exists(engine.url):
            create_database(engine.url)
            print(f"Created database: {app.config['SQLALCHEMY_DATABASE_URI']}")
        
        # Create tables
        db.create_all()
        print("Created database tables")
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Create admin user
            from werkzeug.security import generate_password_hash
            admin = User(
                id='00000000-0000-0000-0000-000000000000',
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin'),
                first_name='Admin',
                last_name='User'
            )
            db.session.add(admin)
            db.session.commit()
            print("Created admin user (username: admin, password: admin)")
    
    print("Database setup complete!")

if __name__ == '__main__':
    setup_database()
