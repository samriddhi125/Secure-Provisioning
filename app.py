import os
from flask import Flask, jsonify, request, session, send_from_directory
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
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
from requests.exceptions import ConnectionError
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Enable CORS with credentials
# In app.py, replace the CORS line with:
CORS(app, 
     supports_credentials=True, 
     origins=['http://127.0.0.1:5001', 'http://localhost:5001'],
     allow_headers=['Content-Type'],
     methods=['GET', 'POST', 'OPTIONS'])

# Initialize components
retriever = RetrieveProviders()
db = TransactionDatabase("transactions.db")
intentExtractor = IntentExtractor()

# Billing Configuration
PLATFORM_FEE = 2.5  # Rupees
MIN_BASE_PRICE = 5.0  # Minimum price for lowest quality
MAX_BASE_PRICE = 40.0  # Maximum price for highest quality

# Quality vector bounds (based on your provider data structure)
# [resolution, frame_rate, region_latency, adaptive_streaming, buffer_strategy]
MIN_VECTOR_SUM = 0.0  # Theoretical minimum (all zeros)
MAX_VECTOR_SUM = 15.0  # Theoretical maximum (4+4+3+2+2)

# --- SERVER-SIDE KEY MANAGEMENT (MODIFIED) ---
server_private_key = None
server_public_key = None
server_public_key_pem_b64 = None # Re-added to send to client

def load_or_generate_server_keys():
    """Loads server keys from env vars or generates them if they don't exist."""
    global server_private_key, server_public_key, server_public_key_pem_b64
    
    priv_key_b64 = os.environ.get("SERVER_PRIVATE_KEY")
    pub_key_b64 = os.environ.get("SERVER_PUBLIC_KEY")

    if priv_key_b64 and pub_key_b64:
        print("✓ Loading server keys from environment variables...")
        try:
            private_key_pem = base64.b64decode(priv_key_b64)
            public_key_pem = base64.b64decode(pub_key_b64)
            
            server_private_key = load_pem_private_key(private_key_pem, password=None)
            server_public_key = load_pem_public_key(public_key_pem)
            
            # --- MODIFIED: Store the b64 public key for the API ---
            server_public_key_pem_b64 = pub_key_b64
            
            print("✓ Server keys loaded successfully.")
        except Exception as e:
            print(f"FAILED TO LOAD KEYS: {e}")
            print("Please check your environment variables. Exiting.")
            exit(1)
    else:
        print("Server keys not found in environment. Generating new keys...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        priv_key_b64_str = base64.b64encode(private_key_pem).decode('utf-8')
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key_b64_str = base64.b64encode(public_key_pem).decode('utf-8')

        print("\n" + "="*80)
        print("PLEASE SET THESE ENVIRONMENT VARIABLES FOR YOUR SERVER ‼️")
        print("\n--- SET `SERVER_PRIVATE_KEY` to this value: ---")
        print(priv_key_b64_str)
        print("\n--- SET `SERVER_PUBLIC_KEY` to this value: ---")
        print(pub_key_b64_str)
        print("\n" + "="*80)
        print("Server will exit. Please set the variables and restart.")
        exit(0)

def sign_payload(payload):
    """Signs a JSON payload with the server's private key."""
    if not server_private_key:
        raise Exception("Server private key is not loaded.")
    
    payload_string = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    payload_bytes = payload_string.encode('utf-8')
    
    signature = server_private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256.digest_size
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')

# ============= DATABASE INITIALIZATION (MODIFIED) =============

def init_db():
    """Initialize database - just verify schema is correct."""
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            print("✓ Database connection successful.")
            cursor = db_conn.cursor
            
            # Verify signature column exists in transactions
            cursor.execute("PRAGMA table_info(transactions)")
            trans_columns = [col[1] for col in cursor.fetchall()]
            
            if 'signature' not in trans_columns:
                print("Adding signature column to transactions table...")
                cursor.execute("ALTER TABLE transactions ADD COLUMN signature TEXT")
                db_conn.conn.commit()
                print("✓ signature column added successfully")

            # CREATE BILLING TABLE - MOVED OUTSIDE THE CONDITIONAL
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS billing (
                    billing_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    transaction_id INTEGER,
                    content_name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    quality_score REAL NOT NULL,
                    quality_vector TEXT,
                    vector_sum REAL,
                    base_price REAL NOT NULL,
                    platform_fee REAL NOT NULL,
                    total_price REAL NOT NULL,
                    payment_status TEXT DEFAULT 'pending',
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
                )
            """)
            db_conn.conn.commit()
            print("✓ Billing table verified/created.")
            
            # Verify users table doesn't have publicKey
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [col[1] for col in cursor.fetchall()]
            
            if 'publicKey' in user_columns:
                print("Removing legacy 'publicKey' column from 'users' table...")
                
                # Create clean users table
                cursor.execute("PRAGMA foreign_keys=off")
                cursor.execute("BEGIN TRANSACTION")
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users_new (
                        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        phone_no TEXT,
                        email TEXT UNIQUE NOT NULL,
                        age INTEGER,
                        password TEXT NOT NULL
                    )
                """)
                
                cursor.execute("""
                    INSERT INTO users_new (user_id, name, phone_no, email, age, password)
                    SELECT user_id, name, phone_no, email, age, password FROM users
                """)
                
                cursor.execute("DROP TABLE users")
                cursor.execute("ALTER TABLE users_new RENAME TO users")
                cursor.execute("COMMIT")
                cursor.execute("PRAGMA foreign_keys=on")
                print("✓ 'publicKey' column removed successfully.")
            
            print("✓ Database schema verified and cleaned. Billing added.")
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        import traceback
        traceback.print_exc()

# ============= BILLING FUNCTIONS =============

def calculate_billing(quality_score, provider_quality_vector=None):
    """
    Calculate billing based on provider quality vector sum.
    
    Args:
        quality_score: Similarity score (0.0 to 1.0) - kept for compatibility
        provider_quality_vector: List of [resolution, frame_rate, region_latency, 
                                          adaptive_streaming, buffer_strategy]
    
    Returns:
        Dictionary with billing information
    """
    if provider_quality_vector:
        # Sum all quality metrics
        vector_sum = sum(provider_quality_vector)
        
        # Normalize to 0-1 range
        normalized_score = (vector_sum - MIN_VECTOR_SUM) / (MAX_VECTOR_SUM - MIN_VECTOR_SUM)
        normalized_score = max(0.0, min(1.0, normalized_score))  # Clamp to [0, 1]
        
        # Linear interpolation between min and max price
        base_price = MIN_BASE_PRICE + (normalized_score * (MAX_BASE_PRICE - MIN_BASE_PRICE))
    else:
        # Fallback: use quality_score directly
        normalized_score = quality_score
        base_price = MIN_BASE_PRICE + (quality_score * (MAX_BASE_PRICE - MIN_BASE_PRICE))
    
    # Round to 2 decimal places
    base_price = round(base_price, 2)
    total_price = round(base_price + PLATFORM_FEE, 2)
    
    return {
        'vector_sum': sum(provider_quality_vector) if provider_quality_vector else None,
        'normalized_score': round(normalized_score, 2),
        'base_price': base_price,
        'platform_fee': PLATFORM_FEE,
        'total_price': total_price,
        'quality_score': quality_score
    }

# ============= FRONTEND ROUTE =============

@app.route('/')
def serve_index():
    """Serves the index.html file."""
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'index.html')

# ============= AUTHENTICATION ENDPOINTS (MODIFIED) =============

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    phone_no = data.get('phone_no', '0000000000')
    age = data.get('age', 18)
    
    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required"}), 400
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            existing = db_conn.get_user_by_email(email)
            
            if existing:
                return jsonify({"error": "Email already registered"}), 400
            
            hashed_password = generate_password_hash(password)
            
            # --- MODIFIED: Inserts into the new, cleaner 'users' table ---
            db_conn.cursor.execute(
                """INSERT INTO users (name, phone_no, email, age, password) 
                   VALUES (?, ?, ?, ?, ?)""",
                (name, phone_no, email, age, hashed_password)
            )
            user_id = db_conn.cursor.lastrowid
            db_conn.conn.commit()
            
            print(f"\n[BACKEND LOG] Registered user '{email}' (ID: {user_id})")
        
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


# ============= ENCRYPTION/SIGNATURE ENDPOINTS (MODIFIED) =============

# --- RE-ADDED /api/public_key route ---
@app.route('/api/public_key', methods=['GET'])
def get_public_key():
    """Provides the client with the server's public key."""
    if not server_public_key_pem_b64:
        return jsonify({"error": "Server key not available"}), 500
        
    return jsonify({"publicKey": server_public_key_pem_b64})


@app.route('/api/confirm_service', methods=['POST'])
def confirm_service():
    """
    (MODIFIED LOGIC)
    Receives a payload from the client, signs it with the server's private key,
    and stores the payload + signature in the database as a non-repudiable log.
    """
    if 'user_email' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    payload = data.get('payload')
    
    if not payload:
        return jsonify({"error": "Payload is required"}), 400

    email = session['user_email']
    print("\n--- [BACKEND LOG] Starting Service Confirmation (Notarization) ---")
    print(f"[BACKEND LOG] Request received from user: {email}")
    print(f"[BACKEND LOG] Payload to sign: {payload}")

    try:
        signature_b64 = sign_payload(payload)
        
        print("✅ [BACKEND LOG] Payload signed successfully.")
        print(f"[DEBUG] Storing Signature: {signature_b64[:30]}...")
        
        # Calculate billing with quality vector
        quality_score = float(payload.get('quality', 0))
        quality_vector = payload.get('quality_vector')  # New field

        billing_info = calculate_billing(quality_score, quality_vector)

        print(f"✓ [BILLING] Calculated billing:")
        print(f"   Quality Vector: {quality_vector}")
        print(f"   Vector Sum: {billing_info.get('vector_sum')}")
        print(f"   Normalized Score: {billing_info['normalized_score']}")
        print(f"   Base Price: ₹{billing_info['base_price']}")
        print(f"   Platform Fee: ₹{billing_info['platform_fee']}")
        print(f"   Total: ₹{billing_info['total_price']}")
        
        try:
            with TransactionDatabase("transactions.db") as db_conn:
                user_id = session['user_id']
                cursor = db_conn.cursor
                cursor.execute(
                    """INSERT INTO transactions 
                       (user_id, action, movie_title, provider, quality, timestamp, signature) 
                       VALUES (?, ?, ?, ?, ?, datetime('now'), ?)""",
                    (user_id, 
                     payload.get('action', 'unknown'),
                     payload.get('movie_title', 'unknown'),
                     payload.get('provider', 'unknown'),
                     payload.get('quality', 'unknown'),
                     signature_b64
                    )
                )

                transaction_id = cursor.lastrowid
                
                # Store billing record
                cursor.execute(
                    """INSERT INTO billing 
                       (user_id, transaction_id, content_name, provider, quality_score, 
                        quality_vector, vector_sum, base_price, platform_fee, total_price, 
                        payment_status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                    (user_id, transaction_id, 
                     payload.get('movie_title', 'unknown'),
                     payload.get('provider', 'unknown'),
                     quality_score,
                     json.dumps(quality_vector) if quality_vector else None,
                     billing_info.get('vector_sum'),
                     billing_info['base_price'],
                     billing_info['platform_fee'],
                     billing_info['total_price'])
                )
                billing_id = cursor.lastrowid

                db_conn.conn.commit()
                print("[BACKEND LOG] Transaction and signature logged successfully")
                print(f"✓ [BILLING] Billing record created with ID: {billing_id}")
                
                # Store billing_id in session for payment
                session['pending_billing_id'] = billing_id
        except Exception as log_error:
            print(f"⚠️ [BACKEND LOG] Failed to log transaction: {log_error}")
            import traceback
            traceback.print_exc()
            return jsonify({
                "status": "error",
                "message": f"Failed to create billing: {str(log_error)}"
            }), 500
        
        return jsonify({
            "status": "success",
            "message": "Service action confirmed and logged by server.",
            "billing_id": billing_id,
            "billing_info": billing_info
        }), 200

    except Exception as e:
        print(f"❌ [BACKEND LOG] Signing error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"Signing failed: {str(e)}"
        }), 500

# --- NEW ENDPOINT: /api/history ---
@app.route('/api/history', methods=['GET'])
def get_history():
    """Fetches the transaction history for the logged-in user."""
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
        
    user_id = session['user_id']
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            transactions = db_conn.cursor.execute(
                "SELECT * FROM transactions WHERE user_id = ?",
                (user_id,)
            ).fetchall()
            
            # Convert list of row objects to list of dicts
            history_list = [dict(row) for row in transactions]
            
            return jsonify(history_list), 200
            
    except Exception as e:
        print(f"❌ [BACKEND LOG] Error fetching history: {e}")
        return jsonify({"error": "Could not retrieve history"}), 500

# --- NEW BILLING ENDPOINTS ---

@app.route('/api/get_pending_bill', methods=['GET'])
def get_pending_bill():
    """Get most recent pending billing information for current user."""
    print("\n" + "="*50)
    print("DEBUG: /api/get_pending_bill called")
    print("="*50)

    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            cursor = db_conn.cursor
            bill = cursor.execute(
                """SELECT * FROM billing 
                   WHERE user_id = ? AND payment_status = 'pending'
                   ORDER BY timestamp DESC
                   LIMIT 1""",
                (session['user_id'],)
            ).fetchone()
            
            if not bill:
                return jsonify({"error": "No pending bill found"}), 404
            
            return jsonify(dict(bill)), 200
    except Exception as e:
        print(f"Error fetching bill: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/process_payment', methods=['POST'])
def process_payment():
    """Process payment for pending bill."""
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    billing_id = data.get('billing_id')
    payment_method = data.get('payment_method', 'card')
    
    if not billing_id:
        return jsonify({"error": "Billing ID required"}), 400
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            cursor = db_conn.cursor
            
            bill = cursor.execute(
                """SELECT * FROM billing 
                   WHERE billing_id = ? AND user_id = ? AND payment_status = 'pending'""",
                (billing_id, session['user_id'])
            ).fetchone()
            
            if not bill:
                return jsonify({"error": "Invalid or already paid bill"}), 404
            
            # Simulate payment processing
            cursor.execute(
                """UPDATE billing SET payment_status = 'completed' 
                   WHERE billing_id = ?""",
                (billing_id,)
            )
            db_conn.conn.commit()
            
            session.pop('pending_billing_id', None)
            
            print(f"[BILLING] Payment processed for billing_id: {billing_id}")
            
            return jsonify({
                "status": "success",
                "message": "Payment processed successfully",
                "billing_id": billing_id,
                "amount_paid": bill['total_price']
            }), 200
            
    except Exception as e:
        print(f"Payment processing error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/billing_history', methods=['GET'])
def billing_history():
    """Get billing history for current user."""
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            cursor = db_conn.cursor
            bills = cursor.execute(
                """SELECT * FROM billing 
                   WHERE user_id = ? 
                   ORDER BY timestamp DESC""",
                (session['user_id'],)
            ).fetchall()
            
            return jsonify([dict(bill) for bill in bills]), 200
    except Exception as e:
        print(f"Error fetching billing history: {e}")
        return jsonify({"error": str(e)}), 500
    
# ============= HELPER FUNCTIONS =============
# ... (cosine_similarity, searcher, intent_helper, find_relevant_helper are all unchanged) ...
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
    
    resolution = 3
    frame_rate = 1
    region_latency = 0
    adaptive_streaming = 0
    buffer_strategy = 1
    
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


# ============= API ENDPOINTS (Unchanged) =============

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "encryption": "server-notarization", 
        "database": "connected"
    }), 200


@app.route('/api/chat', methods=['POST'])
def chat():
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
    query = request.args.get("query")
    if not query:
        return jsonify({"error": "Query is required"}), 400
    
    try:
        return jsonify(searcher(query))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/getIntent", methods=["POST"])
def getIntent():
    """Get intent extraction, NO signature."""
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
    """Find relevant providers, NO signature."""
    query = request.args.get("message")
    if not query:
        return jsonify({"error": "Message is required"}), 400
    
    result = find_relevant_helper(query)
    return jsonify(result)


@app.route("/takeQuery", methods=["POST"])
def takeQuery():
    """Smart search, NO signature."""
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
    """(MODIFIED) View all users and transactions (shows signature)."""
    try:
        with TransactionDatabase("transactions.db") as db_conn:
            # Select from the new, cleaner users table
            users = db_conn.cursor.execute(
                "SELECT user_id, name, email, phone_no, age FROM users"
            ).fetchall()
            transactions = db_conn.cursor.execute(
                "SELECT * FROM transactions"
            ).fetchall()
            
            return jsonify({
                "users": [dict(row) for row in users],
                "transactions": [dict(row)for row in transactions]
            })
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Be more specific if the column is gone
        if "no such column: publicKey" in str(e):
            print("Note: 'publicKey' column no longer exists, which is expected.")
            # If this happens, retry without it
            with TransactionDatabase("transactions.db") as db_conn_retry:
                users = db_conn_retry.cursor.execute(
                    "SELECT user_id, name, email, phone_no, age FROM users"
                ).fetchall()
                transactions = db_conn_retry.cursor.execute(
                    "SELECT * FROM transactions"
                ).fetchall()
                return jsonify({
                    "users": [dict(row) for row in users],
                    "transactions": [dict(row)for row in transactions]
                })

        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n" + "="*60)
    print("STREAMBOT - AI STREAMING ASSISTANT WITH ENCRYPTION")
    print("="*60 + "\n")
    
    load_or_generate_server_keys()
    init_db()
    
    app.run(debug=True, port=5001, host='0.0.0.0')

