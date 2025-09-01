#!/usr/bin/env python3
"""
Start script for the Webproxy Login Portal
"""

import os
import sys

def main():
    # Check if required packages are installed
    try:
        import flask
        import flask_wtf
        import wtforms
        import werkzeug
    except ImportError as e:
        print(f"Error: Missing required package - {e}")
        print("Please install requirements with: pip install -r requirements.txt")
        sys.exit(1)
    
    # Set default secret key if not provided
    if 'SECRET_KEY' not in os.environ:
        print("Warning: Using default SECRET_KEY. Set SECRET_KEY environment variable for production!")
        os.environ['SECRET_KEY'] = 'dev-key-change-in-production'
    
    # Import and run the app
    from app import app, init_db
    
    print("Initializing database...")
    init_db()
    
    print("Starting Webproxy Login Portal...")
    print("Default admin login: username='admin', password='admin123'")
    print("Server will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
