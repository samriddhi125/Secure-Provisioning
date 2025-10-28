from flask import Flask, jsonify, request, session
from flask_cors import CORS
from fetch_complete import RetrieveProviders
import json
import numpy as np
from numpy import dot
from numpy.linalg import norm
import time
from transaction_db import TransactionDatabase
from intent_extractor import IntentExtractor
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
from requests.exceptions import ConnectionError
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Enable CORS with credentials
CORS(app, supports_credentials=True, origins=['http://127.0.0.1:*', 'http://localhost:*'])

# Initialize components
retriever = RetrieveProviders()
db = TransactionDatabase("transactions.db")
intentExtractor = IntentExtractor()


# ============= DATABASE INITIALIZATION =============

def init_db():
    """Initialize database with encryption support."""
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            # Check if publicKey column exists, if not add it
            cursor = db_conn.cursor
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'publicKey' not in columns:
                print("Adding publicKey column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN publicKey TEXT")
                db_conn.conn.commit()
                print("✓ publicKey column added successfully")
            
            print("✓ Database initialized with encryption support")
    except Exception as e:
        print(f"Database initialization error: {e}")


# ============= AUTHENTICATION ENDPOINTS =============

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    public_key_b64 = data.get('publicKey')  # New: Accept public key
    phone_no = data.get('phone_no', '0000000000')
    age = data.get('age', 18)
    
    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required"}), 400
    
    if not public_key_b64:
        return jsonify({"error": "Public key is required for secure transactions"}), 400
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            # Check if user exists
            existing = db_conn.get_user_by_email(email)
            
            if existing:
                return jsonify({"error": "Email already registered"}), 400
            
            # Create user with public key using the add_user method
            hashed_password = generate_password_hash(password)
            user_id = db_conn.add_user(
                name=name,
                phone_no=phone_no,
                email=email,
                age=age,
                password=hashed_password,
                public_key=public_key_b64
            )
            
            print(f"\n[BACKEND LOG] Registered user '{email}' (ID: {user_id}) with encrypted key pair")
        
        return jsonify({"message": "Registration successful"}), 201
    except Exception as e:
        print(f"Registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            user = db_conn.cursor.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            
            if not user:
                return jsonify({"error": "Invalid credentials"}), 401
            
            user_dict = dict(user)
            
            if not check_password_hash(user_dict['password'], password):
                return jsonify({"error": "Invalid credentials"}), 401
            
            # Set session
            session['user_id'] = user_dict['user_id']
            session['user_email'] = user_dict['email']
            session['user_name'] = user_dict['name']
            session.permanent = True
            
            return jsonify({
                "user": {
                    "name": user_dict['name'],
                    "email": user_dict['email']
                }
            }), 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@app.route('/api/user', methods=['GET'])
def get_user():
    if 'user_id' in session:
        return jsonify({
            "name": session['user_name'],
            "email": session['user_email']
        }), 200
    return jsonify({"error": "Not authenticated"}), 401


# ============= ENCRYPTION/SIGNATURE ENDPOINTS =============

@app.route('/api/confirm_service', methods=['POST'])
def confirm_service():
    """Verify cryptographic signature for secure transactions."""
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    payload = data.get('payload')
    signature_b64 = data.get('signature')
    
    if not payload or not signature_b64:
        return jsonify({"error": "Payload and signature are required"}), 400

    email = session['user_email']
    print("\n--- [BACKEND LOG] Starting Signature Verification ---")
    print(f"[BACKEND LOG] Request received from user: {email}")

    try:
        # Fetch public key from database
        with TransactionDatabase("transactions.db") as db_conn:
            user = db_conn.cursor.execute(
                "SELECT publicKey FROM users WHERE email = ?", (email,)
            ).fetchone()
            
            if not user or not user['publicKey']:
                print(f"❌ [BACKEND LOG] Public key for user '{email}' not found")
                return jsonify({"error": "Public key not found. Please re-register."}), 404
            
            public_key_b64 = user['publicKey']

        print("[BACKEND LOG] Public key found. Decoding key and signature...")
        
        # Decode public key and signature
        public_key_der = base64.b64decode(public_key_b64)
        signature = base64.b64decode(signature_b64)
        public_key = load_der_public_key(public_key_der)
        
        # Prepare payload for verification
        payload_string = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        payload_bytes = payload_string.encode('utf-8')
        
        print(f"[BACKEND LOG] Verifying signature against payload: {payload_string}")
        
        # Verify signature
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print("✅ [BACKEND LOG] SIGNATURE VERIFIED SUCCESSFULLY")
        
        # Log the transaction
        try:
            with TransactionDatabase("transactions.db") as db_conn:
                user_id = session['user_id']
                db_conn.cursor.execute(
                    """INSERT INTO transactions 
                       (user_id, action, movie_title, provider, quality, timestamp) 
                       VALUES (?, ?, ?, ?, ?, datetime('now'))""",
                    (user_id, 
                     payload.get('action', 'unknown'),
                     payload.get('movie_title', 'unknown'),
                     payload.get('provider', 'unknown'),
                     payload.get('quality', 'unknown'))
                )
                db_conn.conn.commit()
                print("[BACKEND LOG] Transaction logged successfully")
        except Exception as log_error:
            print(f"⚠️ [BACKEND LOG] Failed to log transaction: {log_error}")
        
        return jsonify({
            "status": "success",
            "message": "Service confirmed: Signature verified!",
            "transaction_id": "Generated transaction ID could go here"
        }), 200

    except InvalidSignature:
        print("❌ [BACKEND LOG] SIGNATURE VERIFICATION FAILED - TAMPERING DETECTED")
        return jsonify({
            "status": "error",
            "message": "Invalid signature. Request rejected for security."
        }), 403
        
    except Exception as e:
        print(f"❌ [BACKEND LOG] Verification error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"Verification failed: {str(e)}"
        }), 500


# ============= HELPER FUNCTIONS =============

def cosine_similarity(a, b):
    """Calculate cosine similarity between two vectors."""
    return dot(a, b) / (norm(a) * norm(b))


def searcher(query):
    """Search for content using the retriever with retry logic."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            return retriever.search(query)
        except ConnectionError as e:
            print(f"⚠️ TMDB connection error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            else:
                raise  # Re-raise after final attempt


def intent_helper(user_message):
    """Extract intents and return movie name and intent vector."""
    if not user_message:
        return None
    
    if not intentExtractor:
        return None
    
    result = {}
    
    try:
        intents = intentExtractor.intent_extractor.extract_intents(user_message)
        intents_dict = intents.to_dict(exclude_none=False)
        
        processed_intents = intentExtractor.process_and_convert_intents(intents_dict)
        movie = intents_dict["movie_details"]["movie_name"]
        result["movie"] = movie
        
        intent_vector = intentExtractor.create_intent_vector(processed_intents)
        result["intent_vector"] = intent_vector
        return result
    except Exception as e:
        print(f"Error extracting intents: {e}")
        import traceback
        traceback.print_exc()
        return result


def find_relevant_helper(query, intent_vector=None):
    """Find relevant providers based on query and intent vector."""
    if not query:
        return {"error": "Query is required"}
    
    print(f"Message: {query}")
    
    # Default preferences
    resolution = 3
    frame_rate = 1
    region_latency = 0
    adaptive_streaming = 0
    buffer_strategy = 1
    
    # Apply custom intent vector if provided
    if intent_vector:
        if intent_vector[0]:
            resolution = intent_vector[0]
        if intent_vector[1]:
            frame_rate = intent_vector[1]
        if intent_vector[2]:
            region_latency = intent_vector[2]
        if intent_vector[3]:
            adaptive_streaming = intent_vector[3]
        if intent_vector[4]:
            buffer_strategy = intent_vector[4]
    
    request_vector = np.array([resolution, frame_rate, region_latency, 
                               adaptive_streaming, buffer_strategy])
    
    try:
        raw_results = json.loads(searcher(query))
        print(f"Request vector: {request_vector}")
        
        final_results = []
        start = time.time()
        
        for content in raw_results:
            providers_arranged = []
            for provider_info in raw_results[content]:
                provider_vector = np.array([
                    provider_info['resolution'],
                    provider_info['frame_rate'],
                    provider_info['region_latency'],
                    provider_info['adaptive_streaming'],
                    provider_info['buffer_strategy']
                ])
                similarity = cosine_similarity(provider_vector, request_vector)
                providers_arranged.append((provider_info['provider'], similarity))
            
            providers_arranged = sorted(providers_arranged, key=lambda x: x[1], reverse=True)
            print(f"Providers for {content}: {providers_arranged}")
            
            final_results.append({content: providers_arranged})
        
        end = time.time()
        print(f"Processing time: {end-start:.3f} seconds")
        
        return final_results
        
    except ConnectionError as e:
        print(f"❌ TMDB API connection failed: {e}")
        return {"error": "Unable to connect to movie database. Please try again later."}
    except Exception as e:
        print(f"❌ Search error: {e}")
        import traceback
        traceback.print_exc()
        return {"error": f"Search failed: {str(e)}"}


# ============= API ENDPOINTS =============

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "encryption": "enabled",
        "database": "connected"
    }), 200


@app.route('/api/chat', methods=['POST'])
def chat():
    """Process chat request and extract intents."""
    data = request.args
    user_message = data.get('message')
    
    if not user_message:
        return jsonify({"error": "Message is required"}), 400
    
    if not intentExtractor:
        return jsonify({
            "error": "Intent extraction service not available",
            "message": user_message
        }), 503
    
    try:
        intents = intentExtractor.intent_extractor.extract_intents(user_message)
        intents_dict = intents.to_dict(exclude_none=False)
        
        processed_intents = intentExtractor.process_and_convert_intents(intents_dict)
        intent_vector = intentExtractor.create_intent_vector(processed_intents)
        
        return jsonify({
            "message": user_message,
            "raw_intents": intents_dict,
            "processed_intents": processed_intents,
            "intent_vector": intent_vector,
        }), 200
    except Exception as e:
        print(f"Error extracting intents: {e}")
        return jsonify({
            "error": f"Failed to extract intents: {str(e)}",
            "message": user_message
        }), 500


@app.route("/fetch", methods=["POST"])
def fetch():
    """Fetch raw search results."""
    query = request.args.get("query")
    if not query:
        return jsonify({"error": "Query is required"}), 400
    
    try:
        return jsonify(searcher(query))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/getIntent", methods=["POST"])
def getIntent():
    """Get intent extraction for a message."""
    query = request.args.get("message")
    if not query:
        return jsonify({"error": "Message is required"}), 400
    
    result = intent_helper(query)
    if result:
        return jsonify(result)
    else:
        return jsonify({"error": "Unable to extract intents"}), 500


@app.route("/findRelevant", methods=["POST"])
def find_relevant():
    """Find relevant providers without intent extraction."""
    query = request.args.get("message")
    if not query:
        return jsonify({"error": "Message is required"}), 400
    
    result = find_relevant_helper(query)
    return jsonify(result)


@app.route("/takeQuery", methods=["POST"])
def takeQuery():
    """Smart search with intent extraction."""
    query = request.args.get("message")
    if not query:
        return jsonify({"error": "Message is required"}), 400
    
    intents = intent_helper(query)
    if not intents:
        return jsonify({"error": "Unable to extract intents"}), 500
    
    content = intents["movie"]
    intent_vector = intents["intent_vector"]
    result = find_relevant_helper(content, intent_vector)
    return jsonify(result)


@app.route("/view-tables", methods=["GET"])
def view_tables():
    """View all users and transactions (admin endpoint)."""
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            users = db_conn.cursor.execute(
                "SELECT user_id, name, email, phone_no, age FROM users"
            ).fetchall()
            transactions = db_conn.cursor.execute(
                "SELECT * FROM transactions"
            ).fetchall()
            
            return jsonify({
                "users": [dict(row) for row in users],
                "transactions": [dict(row) for row in transactions]
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n" + "="*60)
    print("STREAMBOT - AI STREAMING ASSISTANT WITH ENCRYPTION")
    print("="*60 + "\n")
    init_db()
    app.run(debug=True, port=5001, host='0.0.0.0')