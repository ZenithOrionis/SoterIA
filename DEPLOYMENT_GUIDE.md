# Aegis-Swarm // Deployment Guide for Air-Gapped Environments

**CLASSIFICATION: INTERNAL CISO DOCUMENTATION**

## Executive Overview
Aegis-Swarm is engineered with **Universal LLM Abstraction** (Architectural Law 2), meaning the entire autonomous engine is fully decoupled from external commercial APIs. This guide outlines how your internal IT and Security teams can deploy the platform in a 100% disconnected, air-gapped corporate network.

## Prerequisites
- A secure, air-gapped host server (Linux/Windows).
- An internal deployment of [Ollama](https://ollama.com/) (or equivalent local inference server).
- A capable open-weights LLM loaded onto the Ollama server (e.g., `qwen2.5:1.5b`, `llama3`).

---

## Step-by-Step Air-Gap Deployment

### 1. Provision the Inference Server
Ensure your internal Ollama instance is running and accessible within your secure subnet. Note its internal IP and port (e.g., `http://localhost:11434` or a designated internal IP like `http://10.0.0.50:11434`).

### 2. Configure the Aegis-Swarm Environment
Locate the `.env` file in the root directory of the Aegis-Swarm project. You must modify this file to sever all ties to the public internet and route traffic to your internal hardware.

Update the following keys in your `.env` file:
```env
# Switch the engine from CLOUD to LOCAL
ACTIVE_MODE="LOCAL"

# Remove any external API keys (Not required in LOCAL mode)
GEMINI_API_KEY=""

# Specify your locally hosted open-weights model
LOCAL_MODEL="ollama/qwen2.5:1.5b"

# Point to your internal inference server's IP/Port
LOCAL_API_BASE="http://10.0.0.50:11434"
```

### 3. Verify Compliance
Aegis-Swarm includes automated QA compliance scripts to guarantee zero hardcoded commercial APIs exist in the gateway logic. Before deploying, run the following verification script:
```bash
python tests/airgap_test.py
```
*Expected Output:*
```text
[*] Scanning llm_gateway.py for compliance...

✅ PASS: Zero hardcoded external web sockets detected.
✅ PASS: Architectural Law 2 (Universal LLM Abstraction) is intact.

[+] Air-gap readiness verified. Safe for 'ACTIVE_MODE=LOCAL' disconnected deployment.
```

### 4. Launch the Autonomous SOC
With the engine securely pointing to your internal network, launch the background processing loop and the executive frontend:
```bash
# Terminal 1: Start the Swarm Engine
python run_soc.py

# Terminal 2: Start the Executive Dashboard
python -m streamlit run src/ui/app.py
```

---

## Security Guarantee
Because Aegis-Swarm routes **100%** of its AI inference through `litellm` inside `src/services/llm_gateway.py`, changing `ACTIVE_MODE` to `LOCAL` mathematically guarantees that no telemetry, log data, or PII ever leaves your corporate perimeter. The entire incident evaluation pipeline remains completely opaque to external entities.
