"""
Aegis-Swarm -- SOC Main Loop
==============================
Entry point that runs the full ingestion -> analysis pipeline in a loop.

Workflow per iteration:
  1. ``fetch_pending_logs()`` pulls up to 5 pending events from SQLite
     and atomically marks them ``processing``.
  2. Each event is passed to ``tribunal.evaluate_log()`` which fans out
     to the three specialist agents concurrently.
  3. The Tribunal computes a deterministic ``final_score`` and writes
     it back to SQLite with status ``analysed``.
  4. Sleep, then repeat.

Usage
-----
    python run_soc.py                   # default 10s poll interval
    python run_soc.py --interval 5      # 5s poll interval
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Ensure project root is importable
_PROJECT_ROOT = str(Path(__file__).resolve().parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Silence litellm's verbose logging BEFORE any litellm import
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("litellm").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

from src.db.database import init_db  # noqa: E402
from src.services.log_ingestor import fetch_pending_logs  # noqa: E402
from src.services.tribunal import evaluate_log  # noqa: E402

# -- Logging setup --------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-22s  %(levelname)-5s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("aegis.soc")


_EVENT_LABELS = {
    4624: "Successful Logon",
    4625: "Failed Logon (Brute Force?)",
    4688: "Process Created (Suspicious?)",
    7045: "Service Installed (Malicious?)",
}


async def _process_batch(logs: list[dict]) -> None:
    """Run the tribunal on every log in the batch (sequentially per log,
    but each log's 3 agents run concurrently inside evaluate_log)."""
    for log in logs:
        eid = log["event_id"]
        user = log["user_account"]
        ip = log["source_ip"]
        label = _EVENT_LABELS.get(eid, f"Event {eid}")

        print(f"\n  [*] Incoming log: EventID={eid} ({label})")
        print(f"      User={user}  IP={ip}")
        print(f"  [*] Gathering Swarm votes...")

        await evaluate_log(log)


async def run(poll_interval: float = 10.0) -> None:
    """Infinite polling loop: fetch -> analyse -> sleep -> repeat."""
    init_db()

    print()
    print("  " + "=" * 58)
    print("   AEGIS-SWARM  //  SOC Analysis Engine  //  ONLINE")
    print("  " + "=" * 58)
    print(f"   Poll interval : {poll_interval}s")
    print(f"   Agents online : identity_agent, network_agent, endpoint_agent")
    print("  " + "=" * 58)
    print()

    cycle = 0
    try:
        while True:
            cycle += 1
            logs = fetch_pending_logs(batch_size=5)

            if not logs:
                print(f"  [~] Cycle {cycle} -- no pending logs. Sleeping {poll_interval}s...")
            else:
                print(f"\n  [+] Cycle {cycle} -- fetched {len(logs)} pending log(s).")
                await _process_batch(logs)

            await asyncio.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n\n  [!] SOC loop stopped by operator. Goodbye.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis-Swarm SOC main loop")
    parser.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="Seconds between polling cycles (default: 10)",
    )
    args = parser.parse_args()
    asyncio.run(run(poll_interval=args.interval))
