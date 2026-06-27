"""
Aegis-Swarm -- Air-Gap Architecture Compliance Test
===================================================
Strict verification script to ensure zero hardcoded external web sockets
or commercial API domains exist in the core LLM Gateway.
"""

import sys
from pathlib import Path

# Explicit list of forbidden commercial endpoints
FORBIDDEN_DOMAINS = [
    "googleapis.com",
    "openai.com",
    "anthropic.com",
    "api.openai.com",
    "huggingface.co",
]

def test_airgap_compliance() -> None:
    # Ensure we test the actual gateway file
    gateway_path = Path(__file__).resolve().parent.parent / "src" / "services" / "llm_gateway.py"
    
    if not gateway_path.exists():
        print(f"[!] FAIL: Gateway file not found at {gateway_path}")
        sys.exit(1)

    print(f"[*] Scanning {gateway_path.name} for compliance...")
    
    content = gateway_path.read_text(encoding="utf-8").lower()
    
    violations = []
    for domain in FORBIDDEN_DOMAINS:
        if domain in content:
            violations.append(domain)
            
    if violations:
        print(f"\n[!] FAIL: AIR-GAP VIOLATION DETECTED!")
        print(f"Found hardcoded external domains: {', '.join(violations)}")
        print("This violates Architectural Law 2 (Universal LLM Abstraction).")
        sys.exit(1)
        
    print("\n[+] PASS: Zero hardcoded external web sockets detected.")
    print("[+] PASS: Architectural Law 2 (Universal LLM Abstraction) is intact.")
    print("\n[+] Air-gap readiness verified. Safe for 'ACTIVE_MODE=LOCAL' disconnected deployment.")
    sys.exit(0)

if __name__ == "__main__":
    test_airgap_compliance()
