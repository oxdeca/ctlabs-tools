import argparse
import webbrowser
import sys
import os
import uuid
import json
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, send_from_directory, abort, redirect, url_for, request, jsonify, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt

# Package configuration
PACKAGE_NAME = "ctlabs_tools.flashcards"
HTML_FILE    = "flashcards.html"

# Resolve the package directory as a filesystem path
PACKAGE_DIR = Path(__file__).parent

# Create Flask app
app = Flask(__name__, static_folder=str(PACKAGE_DIR), static_url_path='')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Initialize JWT
jwt = JWTManager(app)
create_demo_user()

# In-memory storage for demo purposes (replace with database in production)
USERS = {
    # Format: { "email": { "id": str, "password": str, "cardsets": [] } }
}
CARDSETS = {}
PASSWORD_SALT = "flashcards-app-salt"

def hash_password(password):
    """Simple password hashing (in production, use bcrypt or similar)"""
    import hashlib
    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest()

def create_demo_user():
    """Create a demo user for initial testing"""
    email = "demo@example.com"
    password = "demo123"
    
    if email not in USERS:
        user_id = str(uuid.uuid4())
        USERS[email] = {
            "id": user_id,
            "email": email,
            "password": hash_password(password),
            "created_at": datetime.utcnow().isoformat()
        }
        print(f"\nDemo user created: {email} / {password}")
        print("In production, remove this function and use proper user registration")

def get_user_cardsets(user_id):
    """Get all cardsets for a user"""
    if user_id not in CARDSETS:
        CARDSETS[user_id] = []
    return CARDSETS[user_id]

def find_cardset(user_id, cardset_id):
    """Find a cardset by ID for a user"""
    user_cardsets = get_user_cardsets(user_id)
    for cardset in user_cardsets:
        if cardset["id"] == cardset_id:
            return cardset
    return None

@app.route('/')
@app.route('/index.html')
def serve_flashcards():
    """Redirect root requests to the actual flashcards file"""
    return redirect(url_for('static', filename=HTML_FILE))

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    email = data.get('email', '').lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    user = USERS.get(email)
    if not user or user["password"] != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Create access token
    access_token = create_access_token(identity={
        "id": user["id"],
        "email": user["email"]
    })
    
    return jsonify({
        "token": access_token,
        "user": {
            "id": user["id"],
            "email": user["email"]
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint (optional)"""
    data = request.get_json()
    email = data.get('email', '').lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    if '@' not in email:
        return jsonify({"error": "Invalid email format"}), 400
    
    if email in USERS:
        return jsonify({"error": "Email already registered"}), 400
    
    # Create new user
    user_id = str(uuid.uuid4())
    USERS[email] = {
        "id": user_id,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Create access token
    access_token = create_access_token(identity={
        "id": user_id,
        "email": email
    })
    
    return jsonify({
        "token": access_token,
        "user": {
            "id": user_id,
            "email": email
        }
    }), 201

@app.route('/api/cardsets', methods=['GET'])
@jwt_required()
def list_cardsets():
    """List all cardsets for the authenticated user"""
    current_user = get_jwt_identity()
    user_id = current_user["id"]
    
    user_cardsets = get_user_cardsets(user_id)
    return jsonify(user_cardsets)

@app.route('/api/cardsets', methods=['POST'])
@jwt_required()
def save_cardset():
    """Save or update a cardset"""
    current_user = get_jwt_identity()
    user_id = current_user["id"]
    
    data = request.get_json()
    if not data or 'set' not in data:
        return jsonify({"error": "Invalid cardset data"}), 400
    
    cardset_data = data['set']
    meta = cardset_data.get('meta', {})
    
    # Create new cardset or update existing
    if 'id' in meta and meta['id']:
        # Update existing
        cardset_id = meta['id']
        cardset = find_cardset(user_id, cardset_id)
        if not cardset:
            return jsonify({"error": "Cardset not found"}), 404
        
        # Update the cardset
        cardset['meta'] = {
            **meta,
            "modified": datetime.utcnow().isoformat()
        }
        cardset['cards'] = cardset_data['cards']
    else:
        # Create new
        cardset_id = str(uuid.uuid4())
        cardset = {
            "id": cardset_id,
            "meta": {
                **meta,
                "id": cardset_id,
                "created": datetime.utcnow().isoformat(),
                "modified": datetime.utcnow().isoformat()
            },
            "cards": cardset_data['cards']
        }
        get_user_cardsets(user_id).append(cardset)
    
    return jsonify({
        "id": cardset_id,
        "message": "Cardset saved successfully"
    })

@app.route('/api/cardsets/<cardset_id>', methods=['GET'])
@jwt_required()
def get_cardset(cardset_id):
    """Get a specific cardset"""
    current_user = get_jwt_identity()
    user_id = current_user["id"]
    
    cardset = find_cardset(user_id, cardset_id)
    if not cardset:
        return jsonify({"error": "Cardset not found"}), 404
    
    return jsonify(cardset)

@app.route('/api/cardsets/<cardset_id>', methods=['DELETE'])
@jwt_required()
def delete_cardset(cardset_id):
    """Delete a cardset"""
    current_user = get_jwt_identity()
    user_id = current_user["id"]
    
    user_cardsets = get_user_cardsets(user_id)
    for i, cardset in enumerate(user_cardsets):
        if cardset["id"] == cardset_id:
            del user_cardsets[i]
            return jsonify({"message": "Cardset deleted successfully"})
    
    return jsonify({"error": "Cardset not found"}), 404

@app.errorhandler(404)
def not_found(e):
    # Only handle API 404s specially, serve HTML for root paths
    if request.path.startswith('/api/'):
        return jsonify({"error": "Not Found", "message": str(e.description)}), 404
    return send_from_directory(PACKAGE_DIR, HTML_FILE)

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized", "message": str(e.description)}), 401

def main():
    parser = argparse.ArgumentParser(description="Run the Flashcards app locally")
    parser.add_argument(
        "-H", "--host", 
        type=str, 
        default="127.0.0.1", 
        help="Host IP to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port", 
        type=int, 
        default=8000, 
        help="Port to bind to (default: 8000)"
    )
    parser.add_argument(
        "--no-browser", 
        action="store_true", 
        help="Do not automatically open the web browser"
    )
    
    args = parser.parse_args()
    
    # Browser URL: use localhost even if binding to 0.0.0.0
    browser_host = "localhost" if args.host == "0.0.0.0" else args.host
    url = f"http://{browser_host}:{args.port}"

    print(f"Serving flashcards at {url}")
    print(f"Listening on {args.host}:{args.port}")
    print(f"Static files served from: {PACKAGE_DIR}")
    print("Press Ctrl+C to stop")
    
    if not args.no_browser:
        webbrowser.open(url)
    
    # Run Flask
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
