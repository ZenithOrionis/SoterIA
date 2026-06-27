"""Quick DB verification script."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
from src.db.database import DB_PATH
from src.services.log_ingestor import fetch_pending_logs

conn = sqlite3.connect(str(DB_PATH))
conn.row_factory = sqlite3.Row

print("=" * 70)
print("  SCHEMA")
print("=" * 70)
schema = conn.execute("SELECT sql FROM sqlite_master WHERE name='security_events'").fetchone()
print(schema[0])

print()
print("=" * 70)
print("  ALL ROWS (summary)")
print("=" * 70)
rows = conn.execute(
    "SELECT id, timestamp, source_ip, user_account, event_id, status, threat_score FROM security_events"
).fetchall()
for r in rows:
    d = dict(r)
    print(f"  EventID={d['event_id']}  User={d['user_account']:<16}  IP={d['source_ip']:<18}  Status={d['status']}")
print(f"\n  Total rows: {len(rows)}")
conn.close()

print()
print("=" * 70)
print("  fetch_pending_logs() TEST")
print("=" * 70)
batch = fetch_pending_logs(batch_size=5)
print(f"  Fetched {len(batch)} pending logs.  Status after fetch:")
for log in batch:
    print(f"    id={log['id'][:8]}...  event_id={log['event_id']}  status={log['status']}")

# Verify they were flipped to 'processing' in DB
conn2 = sqlite3.connect(str(DB_PATH))
conn2.row_factory = sqlite3.Row
rows2 = conn2.execute("SELECT id, status FROM security_events").fetchall()
print("\n  DB status after fetch_pending_logs():")
for r in rows2:
    print(f"    id={r['id'][:8]}...  status={r['status']}")
conn2.close()
print("=" * 70)
