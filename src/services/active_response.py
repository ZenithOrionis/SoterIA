import base64
import requests
import logging
from src.config.settings import get_settings

logger = logging.getLogger("soteria.wazuh")
settings = get_settings()

def get_wazuh_token() -> str | None:
    auth_str = f"{settings.WAZUH_USER}:{settings.WAZUH_PASS}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}"}
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        resp = requests.get(f"{settings.WAZUH_API_URL}/security/user/authenticate", headers=headers, verify=False)
        if resp.status_code == 200:
            return resp.json()["data"]["token"]
        else:
            logger.error(f"Wazuh auth failed: {resp.text}")
            return None
    except Exception as e:
        logger.error(f"Failed to connect to Wazuh API: {e}")
        return None

def trigger_firewall_drop(target_ip: str) -> bool:
    if not target_ip or target_ip == "Unknown":
        return False
        
    token = get_wazuh_token()
    if not token:
        return False
        
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "command": "firewall-drop",
        "arguments": [target_ip, "-", "add"],
        "custom": False,
        "alert": {}
    }
    
    logger.info(f"Dispatching firewall-drop Active Response against {target_ip}...")
    try:
        resp = requests.put(
            f"{settings.WAZUH_API_URL}/active-response?agents_list=all", 
            headers=headers, 
            json=payload, 
            verify=False
        )
        if resp.status_code == 200:
            logger.info(f"Active Response successfully dispatched: {resp.json()}")
            return True
        else:
            logger.error(f"Active Response failed: {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Active Response PUT request failed: {e}")
        return False

def trigger_kill_process(agent_id: str, process_id: str) -> bool:
    if not agent_id or agent_id == "Unknown" or not process_id:
        return False
        
    token = get_wazuh_token()
    if not token:
        return False
        
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "command": "kill-process",
        "arguments": [process_id],
        "custom": True,
        "alert": {}
    }
    
    logger.warning(f"Dispatching kill-process Active Response to agent {agent_id} for PID {process_id}...")
    try:
        resp = requests.put(
            f"{settings.WAZUH_API_URL}/active-response?agents_list={agent_id}", 
            headers=headers, 
            json=payload, 
            verify=False
        )
        if resp.status_code == 200:
            logger.info(f"Kill-Process successfully dispatched: {resp.json()}")
            return True
        else:
            logger.error(f"Kill-Process failed: {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Kill-Process PUT request failed: {e}")
        return False
