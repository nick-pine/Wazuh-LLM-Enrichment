# providers/gemini.py

import json
import time
import requests
from providers.api_config import GEMINI_API_KEY, GEMINI_API_URL

HEADERS = {
    "Content-Type": "application/json",
    "x-goog-api-key": GEMINI_API_KEY
}

def query_gemini(alert, model="gemini-2.0-flash"):
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

Only return valid JSON. No commentary or markdown.

Alert JSON:
{json.dumps(alert, indent=2)}
"""

    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    try:
        start = time.time()
        response = requests.post(GEMINI_API_URL, headers=HEADERS, json=payload, timeout=45)
        response.raise_for_status()

        print("[DEBUG] Gemini raw response:")
        print(response.text)

        parsed = response.json()
        candidates = parsed.get("candidates", [])
        if not candidates:
            raise ValueError("No response candidates from Gemini")
        
        text_response = candidates[0]["content"]["parts"][0]["text"].strip()

        # Remove Markdown-style triple backticks and optional json tag
        if text_response.startswith("```"):
            text_response = text_response.replace("```json", "").replace("```", "").strip()

        # Now parse
        enrichment = json.loads(text_response)


        enrichment["llm_model_version"] = model
        enrichment["enriched_by"] = f"{model}@gemini-api"
        enrichment["enrichment_duration_ms"] = int((time.time() - start) * 1000)

        return enrichment

    except Exception as e:
        print(f"[!] Gemini error: {e}")
        return {
            "summary_text": f"Enrichment failed: {e}",
            "tags": [],
            "risk_score": 0,
            "false_positive_likelihood": 1.0,
            "alert_category": "Unknown",
            "remediation_steps": [],
            "related_cves": [],
            "external_refs": [],
            "llm_model_version": model,
            "enriched_by": f"{model}@gemini-api",
            "enrichment_duration_ms": 0
        }
