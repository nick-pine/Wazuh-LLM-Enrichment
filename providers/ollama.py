# providers/ollama.py

import json
import time
import requests

OLLAMA_API = "http://localhost:11434/api/generate"


def query_ollama(alert, model="phi3:mini"):
    prompt = f"""
You are a security assistant. Based on the following Wazuh alert JSON, return structured enrichment in this JSON format:

{{
  "summary_text": "...",
  "tags": ["..."],
  "risk_score": 0-100,
  "false_positive_likelihood": 0.0-1.0,
  "alert_category": "...",
  "remediation_steps": ["..."],
  "related_cves": ["..."],
  "external_refs": ["..."]
}}

Only return the JSON. Do not include any commentary or markdown.

Alert JSON:
{json.dumps(alert, indent=2)}
"""
    try:
        start = time.time()
        response = requests.post(
            OLLAMA_API,
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            },
            timeout=45
        )
        response.raise_for_status()
        raw = response.json().get("response", "").strip()
        enrichment_data = json.loads(raw)

        enrichment_data["llm_model_version"] = f"{model}-ollama"
        enrichment_data["enriched_by"] = f"{model}@WSL"
        enrichment_data["enrichment_duration_ms"] = int((time.time() - start) * 1000)

        return enrichment_data

    except Exception as e:
        print(f"[!] Ollama error: {e}")
        return {
            "summary_text": f"Enrichment failed: {e}",
            "tags": [],
            "risk_score": 0,
            "false_positive_likelihood": 1.0,
            "alert_category": "Unknown",
            "remediation_steps": [],
            "related_cves": [],
            "external_refs": [],
            "llm_model_version": f"{model}-ollama",
            "enriched_by": f"{model}@WSL",
            "enrichment_duration_ms": 0
        }
