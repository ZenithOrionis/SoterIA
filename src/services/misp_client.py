"""
Mock MISP / Threat Intelligence Client
======================================
Simulates querying an external Threat Intelligence Platform (e.g. MISP, OTX)
for known malicious IoCs (Indicators of Compromise).
"""

import logging

logger = logging.getLogger("soteria.misp_client")

# A small mock database of known malicious IoCs for demonstration purposes.
# In a real environment, this would call the MISP REST API.
MOCK_IOC_DATABASE = {
    # Malicious IPs
    "185.153.196.10": {
        "threat_level": "High",
        "campaign": "APT29",
        "description": "Known C2 server for Cozy Bear."
    },
    "45.33.32.156": {
        "threat_level": "Medium",
        "campaign": "Mirai",
        "description": "Botnet scanning node."
    },
    # Malicious Hashes (just examples)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "threat_level": "Critical",
        "campaign": "WannaCry",
        "description": "Ransomware payload."
    }
}

class MispClient:
    def check_ioc(self, ioc: str) -> dict | None:
        """
        Check if an IP, Hash, or Domain is present in the Threat Intel feed.
        Returns the intel context if found, otherwise None.
        """
        if not ioc or ioc == "Unknown":
            return None
            
        # Check against our mock database
        if ioc in MOCK_IOC_DATABASE:
            logger.warning(f"[MISP] Match found for IoC: {ioc}")
            return MOCK_IOC_DATABASE[ioc]
            
        return None

misp_client = MispClient()
