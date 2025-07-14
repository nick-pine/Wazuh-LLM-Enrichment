# Wazuh-LLM-EnrichmentWazuh + LLM Alert Enrichment (WSL, Ollama, VM Dashboard)
=========================================================

This project enriches Wazuh alerts with AI-generated summaries, tags, and remediation suggestions using a local LLM (Phi-3 Mini via Ollama) running inside WSL. Enriched alerts are viewable in a Wazuh Dashboard VM via Elasticsearch.

Components
----------
- WSL (Ubuntu): Environment for Wazuh Manager + enrichment script
- Wazuh Manager: Runs in WSL to generate security alerts
- Ollama + Phi-3: Local LLM to summarize and tag Wazuh alerts
- Wazuh OVA VM: Runs Elasticsearch and the Wazuh Dashboard (Kibana)
- enrich_alerts.py: Python script to enrich alerts and push to Elasticsearch

Setup Instructions
------------------

1. Install WSL & Ubuntu on Windows 11:

   wsl --install -d Ubuntu

2. Install Wazuh Manager in WSL:

   curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
   sudo bash wazuh-install.sh --wazuh-manager
   sudo systemctl status wazuh-manager

3. Install Ollama in WSL:

   curl -fsSL https://ollama.com/install.sh | sh
   ollama pull phi3:mini
   curl http://localhost:11434

4. Clone and Configure Enrichment Script:

   git clone https://github.com/your-org/wazuh-llm.git
   cd wazuh-llm

   Edit enrich_alerts.py to match your environment:

     OLLAMA_API = "http://localhost:11434/api/generate"
     ELASTICSEARCH_URL = "https://<VM_IP>:9200"
     ELASTIC_USER = "admin"
     ELASTIC_PASS = "admin"
     ENRICHED_INDEX = "wazuh-enriched-alerts"

   Run it:

     sudo python3 enrich_alerts.py

5. Import the Wazuh OVA in VirtualBox:

   https://documentation.wazuh.com/current/deployment-options/virtual-machine.html

   - Start the VM
   - Get its IP address with `ip a`
   - Open the dashboard: http://<VM_IP>:5601
   - Login: admin / admin

6. Create Index Pattern in Kibana:

   - Go to Stack Management → Index Patterns
   - Name: wazuh-enriched-alerts*
   - Time Field: timestamp

   Go to "Discover" to view alerts.

Sample Enriched Alert Format
----------------------------

{
  "alert_id": "1752275717.0",
  "timestamp": "2025-07-13T23:12:45Z",
  "alert": { ... },
  "enrichment": {
    "summary_text": "Login session for user 'root' closed via PAM.",
    "tags": ["PAM", "Login", "RootUser"],
    "risk_score": 40,
    "false_positive_likelihood": 0.2,
    "alert_category": "Login",
    "remediation_steps": [
      "Review PAM configuration",
      "Audit session logs"
    ],
    "related_cves": [],
    "external_refs": [
      "https://attack.mitre.org/techniques/T1078/"
    ],
    "llm_model_version": "phi3:mini-v1.0.0-ollama",
    "enriched_by": "phi3-mini@WSL",
    "enrichment_duration_ms": 1320
  }
}

Useful Commands
---------------

- Check status:	     sudo systemctl status wazuh-manager
- Start Wazuh:	     sudo systemctl start wazuh-manager
- Stop Wazuh:        sudo systemctl stop wazuh-manager
- Stop Ollama:       sudo pkill -f ollama   OR   wsl --shutdown
- Restart Ollama:    ollama serve
- View Elasticsearch data:
    curl -k -u admin:admin https://<VM_IP>:9200/wazuh-enriched-alerts/_search?pretty

Requirements
------------

- Windows 11 with WSL2
- VirtualBox (or other hypervisor)
- Ubuntu 22.04 in WSL
- Python 3.10+
- Ollama + Phi model
- Wazuh OVA virtual appliance
- 4–8 GB RAM recommended
