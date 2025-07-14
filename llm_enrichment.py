# llm_enrichment.py

import json
import time
import requests
from datetime import datetime, timezone
from providers.ollama import query_ollama
# from providers.claude import query_claude  # (for future use)
# from providers.openai import query_openai  # (for future use)

# === CONFIG ===
ALERT_LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
ENRICHED_OUTPUT_PATH = "llm_enriched_alerts.json"

# Choose LLM provider and model
LLM_PROVIDER = "ollama"
LLM_MODEL = "phi3:mini"

# Elasticsearch config
ELASTICSEARCH_URL = "https://192.168.1.173:9200"
ELASTIC_USER = "admin"
ELASTIC_PASS = "admin"
ENRICHED_INDEX = "wazuh-enriched-alerts"

def call_llm_enrichment(alert):
    if LLM_PROVIDER == "ollama":
        return query_ollama(alert, model=LLM_MODEL)
    # elif LLM_PROVIDER == "claude":
    #     return query_claude(alert, model="claude-haiku")
    # elif LLM_PROVIDER == "openai":
    #     return query_openai(alert, model="gpt-4")
    else:
        raise ValueError(f"Unsupported LLM provider: {LLM_PROVIDER}")

def post_to_elasticsearch(doc):
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ENRICHED_INDEX}/_doc",
            json=doc,
            auth=(ELASTIC_USER, ELASTIC_PASS),
            verify=False
        )
        response.raise_for_status()
        print(f"[\u2713] Alert {doc['alert_id']} sent to Elasticsearch")
    except Exception as e:
        print(f"[!] Elasticsearch error: {e}")

def main():
    seen = set()
    print(f"[*] Starting alert enrichment with {LLM_MODEL} via {LLM_PROVIDER}...")

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
                enriched = call_llm_enrichment(alert)

                output = {
                    "alert_id": alert_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert": alert,
                    "enrichment": enriched
                }

                with open(ENRICHED_OUTPUT_PATH, 'a') as out:
                    out.write(json.dumps(output) + "\n")

                post_to_elasticsearch(output)

            except Exception as e:
                print(f"[!] Error handling alert: {e}")

if __name__ == "__main__":
    main()
