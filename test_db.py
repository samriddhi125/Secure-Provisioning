from transaction_db import TransactionDatabase

db = TransactionDatabase("transactions.db")
user_id = db.add_user("sejal", "1231231321", "ver@gmail.com", 25)
db.add_transaction(user_id, "payment", 12345, "PoS_X", 67890, 150.50, "pending")