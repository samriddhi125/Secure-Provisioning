import sqlite3
from typing import Optional, List, Dict, Any
from pathlib import Path


class TransactionDatabase:
    def __init__(self, db_path: str = "transactions.db"):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._connect()
        self._initialize_tables()
    
    def _connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        self.cursor = self.conn.cursor()
    
    def _initialize_tables(self):
        # Create users table with publicKey support
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone_no TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                age INTEGER NOT NULL,
                password TEXT NOT NULL,
                publicKey TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create transactions table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT,
                movie_title TEXT,
                provider TEXT,
                quality TEXT,
                intent TEXT,
                intent_hash INTEGER,
                PoS TEXT,
                PoS_hash INTEGER,
                cost REAL,
                dispute_status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)
        
        self.conn.commit()
        
        # Check if publicKey column exists, if not add it (for existing databases)
        self._ensure_public_key_column()
    
    def _ensure_public_key_column(self):
        """Ensure publicKey column exists in users table."""
        try:
            self.cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in self.cursor.fetchall()]
            
            if 'publicKey' not in columns:
                print("Adding publicKey column to users table...")
                self.cursor.execute("ALTER TABLE users ADD COLUMN publicKey TEXT")
                self.conn.commit()
                print("✓ publicKey column added successfully")
        except Exception as e:
            print(f"Error ensuring publicKey column: {e}")
    
    # User Management Methods
    def add_user(self, name: str, phone_no: str, email: str, age: int, 
                 password: str, public_key: Optional[str] = None) -> int:
        """
        Add a new user to the database.
        
        Args:
            name: User's name
            phone_no: User's phone number
            email: User's email address
            age: User's age
            password: User's hashed password
            public_key: User's public key for encryption (base64 encoded)
            
        Returns:
            int: The user_id of the newly created user
        """
        self.cursor.execute("""
            INSERT INTO users (name, phone_no, email, age, password, publicKey)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, phone_no, email, age, password, public_key))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve user details by user_id.
        
        Args:
            user_id: The user's ID
            
        Returns:
            Dict containing user details or None if not found
        """
        self.cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user details by email.
        
        Args:
            email: The user's email
            
        Returns:
            Dict containing user details or None if not found
        """
        self.cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """
        Update user details.
        
        Args:
            user_id: The user's ID
            **kwargs: Fields to update (name, phone_no, email, age, publicKey)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        allowed_fields = {'name', 'phone_no', 'email', 'age', 'publicKey'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not fields:
            return False
        
        set_clause = ", ".join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [user_id]
        
        self.cursor.execute(f"UPDATE users SET {set_clause} WHERE user_id = ?", values)
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def get_public_key(self, email: str) -> Optional[str]:
        """
        Retrieve user's public key by email.
        
        Args:
            email: The user's email
            
        Returns:
            str: Base64 encoded public key or None if not found
        """
        self.cursor.execute("SELECT publicKey FROM users WHERE email = ?", (email,))
        row = self.cursor.fetchone()
        return row['publicKey'] if row and row['publicKey'] else None
    
    # Transaction Management Methods
    def add_transaction(self, user_id: int, action: Optional[str] = None,
                       movie_title: Optional[str] = None, provider: Optional[str] = None,
                       quality: Optional[str] = None, intent: Optional[str] = None, 
                       intent_hash: Optional[int] = None, pos: Optional[str] = None, 
                       pos_hash: Optional[int] = None, cost: Optional[float] = None,
                       dispute_status: Optional[str] = None) -> int:
        """
        Add a new transaction to the database.
        
        Args:
            user_id: User ID
            action: Action performed (e.g., 'stream_content')
            movie_title: Movie/show title
            provider: Streaming provider
            quality: Video quality
            intent: Transaction intent
            intent_hash: Hash of the intent
            pos: Point of Sale
            pos_hash: Hash of the PoS
            cost: Transaction cost
            dispute_status: Status of any dispute (optional)
            
        Returns:
            int: The transaction_id of the newly created transaction
        """
        self.cursor.execute("""
            INSERT INTO transactions 
            (user_id, action, movie_title, provider, quality, intent, intent_hash, 
             PoS, PoS_hash, cost, dispute_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, action, movie_title, provider, quality, intent, 
              intent_hash, pos, pos_hash, cost, dispute_status))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_transaction(self, transaction_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve transaction details by transaction_id.
        
        Args:
            transaction_id: The transaction ID
            
        Returns:
            Dict containing transaction details or None if not found
        """
        self.cursor.execute("SELECT * FROM transactions WHERE transaction_id = ?", 
                          (transaction_id,))
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def get_user_transactions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve all transactions for a specific user.
        
        Args:
            user_id: The user's ID
            
        Returns:
            List of dictionaries containing transaction details
        """
        self.cursor.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", 
                          (user_id,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def update_dispute_status(self, transaction_id: int, 
                             dispute_status: str) -> bool:
        """
        Update the dispute status of a transaction.
        
        Args:
            transaction_id: The transaction ID
            dispute_status: New dispute status
            
        Returns:
            bool: True if update successful, False otherwise
        """
        self.cursor.execute("""
            UPDATE transactions SET dispute_status = ? 
            WHERE transaction_id = ?
        """, (dispute_status, transaction_id))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def get_transactions_by_dispute_status(self, 
                                          dispute_status: str) -> List[Dict[str, Any]]:
        """
        Retrieve all transactions with a specific dispute status.
        
        Args:
            dispute_status: The dispute status to filter by
            
        Returns:
            List of dictionaries containing transaction details
        """
        self.cursor.execute("SELECT * FROM transactions WHERE dispute_status = ?", 
                          (dispute_status,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Retrieve all users (excluding passwords).
        
        Returns:
            List of dictionaries containing user details
        """
        self.cursor.execute("""
            SELECT user_id, name, phone_no, email, age, created_at 
            FROM users
        """)
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_all_transactions(self) -> List[Dict[str, Any]]:
        """
        Retrieve all transactions.
        
        Returns:
            List of dictionaries containing transaction details
        """
        self.cursor.execute("SELECT * FROM transactions ORDER BY timestamp DESC")
        return [dict(row) for row in self.cursor.fetchall()]
    
    # Utility Methods
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Example usage
if __name__ == "__main__":
    from werkzeug.security import generate_password_hash
    
    # Initialize database
    db = TransactionDatabase("transactions.db")
    
    # Add a user with public key
    user_id = db.add_user(
        name="Sam K",
        phone_no="6775657567",
        email="samk@example.com",
        age=25,
        password=generate_password_hash("password123"),
        public_key="BASE64_ENCODED_PUBLIC_KEY_HERE"
    )
    print(f"Created user with ID: {user_id}")
    
    # Add a transaction
    transaction_id = db.add_transaction(
        user_id=user_id,
        action="stream_content",
        movie_title="Inception",
        provider="Netflix",
        quality="4K",
        intent="Watch movie in high quality",
        intent_hash=123456789012345,
        pos="zeestar",
        pos_hash=987654321098765,
        cost=9.99,
        dispute_status="none"
    )
    print(f"Created transaction with ID: {transaction_id}")
    
    # Retrieve user details
    user = db.get_user(user_id)
    print(f"\nUser details: {user}")
    
    # Get public key
    public_key = db.get_public_key("samk@example.com")
    print(f"\nPublic Key: {public_key}")
    
    # Retrieve user transactions
    transactions = db.get_user_transactions(user_id)
    print(f"\nUser transactions: {transactions}")
    
    # Update dispute status
    db.update_dispute_status(transaction_id, "resolved")
    print(f"\nUpdated dispute status")
    
    # Close connection
    db.close()