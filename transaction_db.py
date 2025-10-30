import sqlite3
from contextlib import contextmanager

class TransactionDatabase:
    def __init__(self, db_name="transactions.db"):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database tables if they don't exist."""
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create users table (WITHOUT publicKey column)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone_no TEXT,
                email TEXT UNIQUE NOT NULL,
                age INTEGER,
                password TEXT NOT NULL
            )
        """)
        
        # Create transactions table (WITH signature column)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                movie_title TEXT NOT NULL,
                provider TEXT NOT NULL,
                quality TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                signature TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        conn.commit()
        conn.close()
        print("✓ Database tables initialized (users, transactions)")
    
    def __enter__(self):
        """Context manager entry."""
        self.conn = sqlite3.connect(self.db_name)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        return False
    
    def get_user_by_email(self, email):
        """Fetch a user by email."""
        if not self.cursor:
            raise RuntimeError("Database not opened. Use context manager.")
        
        result = self.cursor.execute(
            "SELECT * FROM users WHERE email = ?", 
            (email,)
        ).fetchone()
        
        return dict(result) if result else None
    
    def get_user_transactions(self, user_id):
        """Fetch all transactions for a user."""
        if not self.cursor:
            raise RuntimeError("Database not opened. Use context manager.")
        
        results = self.cursor.execute(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
            (user_id,)
        ).fetchall()
        
        return [dict(row) for row in results]
    
    def add_transaction(self, user_id, action, movie_title, provider, quality, signature):
        """Add a new transaction with signature."""
        if not self.cursor:
            raise RuntimeError("Database not opened. Use context manager.")
        
        self.cursor.execute(
            """INSERT INTO transactions 
               (user_id, action, movie_title, provider, quality, timestamp, signature) 
               VALUES (?, ?, ?, ?, ?, datetime('now'), ?)""",
            (user_id, action, movie_title, provider, quality, signature)
        )
        
        return self.cursor.lastrowid