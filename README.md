# SoterIA: Autonomous Threat Tribunal

![SoterIA Header](https://img.shields.io/badge/Status-Active-00ff88?style=for-the-badge)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)
![Ollama](https://img.shields.io/badge/Powered_by-Ollama-white?style=for-the-badge)

<br>
<img src="assets/screenshot.png" alt="SoterIA Dashboard Mockup" width="100%">
<br>

SoterIA is an elite, autonomous Security Operations Center (SOC) platform designed for fully air-gapped environments. It utilizes a multi-agent LLM swarm to continuously ingest, triage, and score security events in real time. 

Featuring an advanced **Threat Tribunal** and an integrated **CISO Copilot**, SoterIA allows you to query your live database with natural language to investigate active threats, lateral movement, and critical infrastructure attacks.

## Core Features
*   **Agentic Swarm Triage:** Autonomous AI agents (Identity, Network, Endpoint) analyze raw logs and vote on severity using a consensus-based Threat Tribunal.
*   **Fully Air-Gapped:** 100% local LLM execution via Ollama (`llama3.2`). No API keys, no data exfiltration.
*   **CISO Copilot:** An interactive, contextual AI assistant that answers questions directly based on the live security event SQLite database.
*   **CrowdStrike-Inspired UI:** Sleek, high-performance Streamlit dashboard featuring live telemetry, event queues, and lateral movement topology graphs.
*   **Mock Attack Generator:** Built-in threat simulator (`mock_generator.py`) to inject Brute Force, Malicious Services, and Suspicious PowerShell events for testing.

## Installation

Ensure you have Python 3.10+ and [Ollama](https://ollama.ai) installed on your system.

```bash
# 1. Clone the repository
git clone https://github.com/ZenithOrionis/SoterIA.git
cd SoterIA

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pull the local LLM via Ollama
ollama pull llama3.2
```

## Running the SOC

SoterIA consists of two main components: the background autonomous engine and the Streamlit frontend.

### 1. Start the Autonomous Engine
Run the SOC engine to start listening for events and processing the AI Tribunal.
```bash
python run_soc.py
```

### 2. Launch the Command Dashboard
In a separate terminal, launch the Streamlit interface.
```bash
python -m streamlit run src/ui/app.py
```

### 3. (Optional) Inject Test Threats
Want to see the agents in action? Use the mock generator to simulate attacks:
```bash
python -c "import sys; sys.path.append('.'); from src.services.mock_generator import run; run(max_count=10)"
```

## Architecture
- **Data Layer:** SQLite (`data/soc_logs.db`)
- **Backend Swarm:** Python `asyncio`, LiteLLM Gateway
- **Frontend Dashboard:** Streamlit, Plotly, Custom CSS

## License
Refer to the `LICENSE` file for details.
