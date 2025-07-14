import json
import time
import requests
from datetime import datetime, timezone

# === CONFIG ===
ALERT_LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
ENRICHED_OUTPUT_PATH = "llm_enriched_alerts.json"
OLLAMA_MODEL = "phi3:mini"
OLLAMA_API = "http://localhost:11434/api/generate"

# Elasticsearch config
ELASTICSEARCH_URL = "https://192.168.1.173:9200"
ELASTIC_USER = "admin"
ELASTIC_PASS = "admin"
ENRICHED_INDEX = "wazuh-enriched-alerts"

def enrich_with_phi(alert):
    prompt = f"""
You are a security assistant. Summarize and classify this Wazuh alert. 
Return a short summary, tags, and optionally remediation suggestions.

Alert JSON:
{json.dumps(alert, indent=2)}
"""
    try:
        response = requests.post(
            OLLAMA_API,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=30
        )
        response.raise_for_status()
        result = response.json().get("response", "").strip()

        return {
            "summary_text": result
        }

    except Exception as e:
        print(f"[!] LLM ERROR: {e}")
        return {
            "summary_text": f"Enrichment failed: {e}"
        }

# push enriched alert to Elasticsearch
def post_to_elasticsearch(doc):
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ENRICHED_INDEX}/_doc",
            json=doc,
            auth=(ELASTIC_USER, ELASTIC_PASS),
            verify=False  # bypass self-signed cert warning
        )
        response.raise_for_status()
        print(f"[✓] Alert {doc['alert_id']} sent to Elasticsearch")
    except Exception as e:
        print(f"[!] Elasticsearch error: {e}")

def main():
    seen = set()
    print("[*] Starting alert enrichment with Phi-3 Mini...")

    with open(ALERT_LOG_PATH, 'r') as logfile:
        while True:
            line = logfile.readline()
            if not line:
                time.sleep(1)
                continue

            try:
                alert = json.loads(line)
                alert_id = alert.get("id") or f"{alert.get('timestamp')}_{alert.get('rule', {}).get('id')}"
                if alert_id in seen:
                    continue
                seen.add(alert_id)

                print(f"[+] Enriching alert {alert_id}...")

                enriched = enrich_with_phi(alert)
                output = {
                    "alert_id": alert_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert": alert,
                    "enrichment": enriched
                }

                # Save locally
                with open(ENRICHED_OUTPUT_PATH, 'a') as out:
                    out.write(json.dumps(output) + "\n")

                # Push to Elasticsearch 🚀
                post_to_elasticsearch(output)

            except Exception as e:
                print(f"[!] Error handling alert: {e}")

if __name__ == "__main__":
    main()

