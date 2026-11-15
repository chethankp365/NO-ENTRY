"""
Optional Hugging Face zero-shot intent classification.
Discovers a warm zero-shot classification endpoint dynamically when HF_TOKEN is configured
and HF_MODEL is not explicitly overridden. Never blocks Ghost or overrides explicit quick actions.
"""

from typing import Any, Dict, Optional, Tuple
import httpx

from backend.app.config import settings
from backend.app.ai.safety import scrub_secrets

CANDIDATE_LABELS = [
    "hint",
    "explanation",
    "log_analysis",
    "rule_review",
    "general_cybersecurity",
]

EXPLICIT_ACTION_MAP = {
    "hint": "hint",
    "explain_log": "log_analysis",
    "why_it_worked": "explanation",
    "review_rule": "rule_review",
}

HF_DISCOVERY_URL = (
    "https://huggingface.co/api/models"
    "?pipeline_tag=zero-shot-classification&inference=warm&sort=downloads&direction=-1&limit=3"
)


class IntentClassifier:
    def __init__(self):
        self._discovered_model: Optional[str] = None

    def is_configured(self) -> bool:
        return bool((settings.HF_TOKEN or "").strip())

    def model_name(self) -> str:
        override = (settings.HF_MODEL or "").strip()
        return override or self._discovered_model or "auto"

    def get_status(self) -> Dict[str, Any]:
        configured = self.is_configured()
        return {
            "configured": configured,
            "model": self.model_name(),
            "status": "ready" if configured else "unconfigured_local_fallback",
        }

    def _local_classify(self, message: str, stage: str = "") -> str:
        low = (message or "").lower()
        if any(k in low for k in ("rule", "sigma", "yaml", "false positive", "detection", "selection", "condition")):
            return "rule_review"
        if any(k in low for k in ("log", "apache", "modsecurity", "wazuh", "syslog", "403", "200", "event")):
            return "log_analysis"
        if any(k in low for k in ("hint", "nudge", "stuck", "next step", "what command", "how do i")):
            return "hint"
        if any(k in low for k in ("why", "how did", "explain", "mitre", "technique", "worked", "stopped")):
            return "explanation"
        if stage in ("attacker", "flag"):
            return "hint"
        if stage == "defender":
            return "rule_review"
        return "general_cybersecurity"

    async def _resolve_model(self, client: httpx.AsyncClient) -> Optional[str]:
        override = (settings.HF_MODEL or "").strip()
        if override:
            return override
        if self._discovered_model:
            return self._discovered_model

        try:
            disc = await client.get(HF_DISCOVERY_URL)
            if disc.status_code == 200:
                items = disc.json() or []
                if isinstance(items, list):
                    for item in items:
                        mid = str((item or {}).get("id") or "").strip()
                        if mid:
                            self._discovered_model = mid
                            return mid
        except Exception:
            pass
        return None

    async def classify(
        self,
        message: str,
        explicit_action: str = "auto",
        stage: str = "",
    ) -> Tuple[str, str]:
        """
        Return `(resolved_intent, classification_source)`.
        Explicit quick actions are NEVER overridden.
        """
        action_key = (explicit_action or "auto").strip().lower()
        if action_key in EXPLICIT_ACTION_MAP:
            return EXPLICIT_ACTION_MAP[action_key], "explicit_action"

        cleaned = (message or "").strip()
        if not cleaned:
            return self._local_classify("", stage), "local_fallback"

        token = (settings.HF_TOKEN or "").strip()
        if not token:
            return self._local_classify(cleaned, stage), "local_fallback"

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                model_id = await self._resolve_model(client)
                if not model_id:
                    return self._local_classify(cleaned, stage), "local_fallback"

                url = f"https://router.huggingface.co/hf-inference/models/{model_id}"
                headers = {"Authorization": f"Bearer {token}"}
                payload = {
                    "inputs": cleaned[:600],
                    "parameters": {"candidate_labels": CANDIDATE_LABELS},
                }
                resp = await client.post(url, headers=headers, json=payload)

            if resp.status_code in (401, 402, 403, 404, 429, 503) or resp.status_code >= 400:
                return self._local_classify(cleaned, stage), f"local_fallback_http_{resp.status_code}"

            data = resp.json()
            # HF router may return {"labels": [...], "scores": [...]} or list of {"label", "score"}
            if isinstance(data, dict) and isinstance(data.get("labels"), list) and data["labels"]:
                top = str(data["labels"][0]).strip()
                if top in CANDIDATE_LABELS:
                    return top, "huggingface"
            elif isinstance(data, list) and data and isinstance(data[0], dict) and "label" in data[0]:
                top = str(data[0]["label"]).strip()
                if top in CANDIDATE_LABELS:
                    return top, "huggingface"
        except Exception as exc:
            _ = scrub_secrets(str(exc))
            return self._local_classify(cleaned, stage), "local_fallback_error"

        return self._local_classify(cleaned, stage), "local_fallback"


intent_classifier = IntentClassifier()
