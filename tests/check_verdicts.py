"""Quick check: did the tribunal write verdicts to the DB?"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
from src.db.database import DB_PATH

conn = sqlite3.connect(str(DB_PATH))
conn.row_factory = sqlite3.Row

rows = conn.execute(
    "SELECT id, event_id, user_account, source_ip, status, threat_score FROM security_events"
).fetchall()

print("=" * 70)
print("  DB STATE AFTER SOC RUN")
print("=" * 70)
for r in rows:
    d = dict(r)
    print(
        f"  EventID={d['event_id']:<5}  "
        f"User={d['user_account']:<16}  "
        f"IP={d['source_ip']:<18}  "
        f"Status={d['status']:<12}  "
        f"Score={d['threat_score']}"
    )
print("=" * 70)
conn.close()
