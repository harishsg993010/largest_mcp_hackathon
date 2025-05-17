#!/usr/bin/env python
"""
Database Reset Script
This script drops and recreates all tables in the database to match the current models.
"""

import os
import sys

# Add the current directory to the path so we can import the backend modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the database and app
from backend.models import db
from backend.app import app

def reset_database():
    """Drop and recreate all tables in the database"""
    print("Resetting database...")
    
    # Use the app context
    with app.app_context():
        # Drop all tables
        print("Dropping all tables...")
        db.drop_all()
        
        # Create all tables
        print("Creating all tables...")
        db.create_all()
        
        print("Database reset complete!")

if __name__ == "__main__":
    reset_database()
