import sqlite3
import os

db_path = os.path.join("data", "soc_logs.db")
conn = sqlite3.connect(db_path)
conn.execute("UPDATE security_events SET status = 'pending'")
conn.commit()
conn.close()
print("Successfully reset security_events status to 'pending'")
