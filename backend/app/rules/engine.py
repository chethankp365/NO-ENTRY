"""
Sigma-Style Detection Rule Engine for NO ENTRY
Parses YAML detection rules with field modifiers (|contains, |startswith, |endswith, |regex)
and evaluates them against structured event and log dictionaries.
"""

import re
from typing import Dict, List, Any, Optional, Union
import yaml
from pydantic import BaseModel, Field

class MatchResult(BaseModel):
    rule_title: str
    matched_lines: List[Dict[str, Any]]
    count: int
    false_positives: List[Dict[str, Any]]
    total_evaluated: int

class DetectionRule(BaseModel):
    title: str
    id: Optional[str] = None
    description: Optional[str] = None
    level: Optional[str] = "medium"
    logsource: Dict[str, Any] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)

def _match_field_condition(log_val: Any, modifier: Optional[str], target_val: Any) -> bool:
    if log_val is None:
        return False
    str_val = str(log_val)

    if modifier == "contains":
        targets = target_val if isinstance(target_val, list) else [target_val]
        str_val_lower = str_val.lower()
        return any(str(t).lower() in str_val_lower for t in targets)

    elif modifier == "startswith":
        targets = target_val if isinstance(target_val, list) else [target_val]
        str_val_lower = str_val.lower()
        return any(str_val_lower.startswith(str(t).lower()) for t in targets)

    elif modifier == "endswith":
        targets = target_val if isinstance(target_val, list) else [target_val]
        str_val_lower = str_val.lower()
        return any(str_val_lower.endswith(str(t).lower()) for t in targets)

    elif modifier == "regex":
        pattern = str(target_val)
        return bool(re.search(pattern, str_val, re.IGNORECASE))

    else:
        # Exact match or in list
        if isinstance(target_val, list):
            return str_val.lower() in [str(t).lower() for t in target_val]
        return str_val.lower() == str(target_val).lower()

def evaluate_selection(selection_spec: Dict[str, Any], log: Dict[str, Any]) -> bool:
    """Evaluate a single selection block against a log record."""
    for key, expected in selection_spec.items():
        if "|" in key:
            field_name, modifier = key.split("|", 1)
        else:
            field_name, modifier = key, None

        log_val = log.get(field_name)
        if log_val is None and "." in field_name:
            # support nested keys like event.action
            parts = field_name.split(".")
            curr = log
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    curr = None
                    break
            log_val = curr

        if not _match_field_condition(log_val, modifier, expected):
            return False
    return True

class RuleEngine:
    @staticmethod
    def parse_rule_yaml(yaml_content: str) -> DetectionRule:
        data = yaml.safe_load(yaml_content)
        return DetectionRule(
            title=data.get("title", "Untitled Rule"),
            id=data.get("id"),
            description=data.get("description"),
            level=data.get("level", "medium"),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {})
        )

    @classmethod
    def evaluate_rule(
        cls,
        rule: DetectionRule,
        logs: List[Dict[str, Any]],
        expected_matches: Optional[List[int]] = None
    ) -> MatchResult:
        detection = rule.detection
        condition = detection.get("condition", "selection").strip()
        matched: List[Dict[str, Any]] = []
        unmatched: List[Dict[str, Any]] = []

        # Find selection keys (anything in detection except 'condition')
        selection_keys = [k for k in detection.keys() if k != "condition"]

        for idx, log in enumerate(logs):
            results = {}
            for sel_name in selection_keys:
                sel_spec = detection[sel_name]
                if isinstance(sel_spec, dict):
                    results[sel_name] = evaluate_selection(sel_spec, log)
                else:
                    results[sel_name] = False

            # Evaluate condition
            is_match = False
            if condition == "selection":
                is_match = results.get("selection", False)
            elif condition == "selection and not filter":
                is_match = results.get("selection", False) and not results.get("filter", False)
            elif condition == "selection1 or selection2":
                is_match = results.get("selection1", False) or results.get("selection2", False)
            elif " or " in condition:
                parts = [p.strip() for p in condition.split(" or ")]
                is_match = any(results.get(p, False) for p in parts)
            elif " and " in condition:
                parts = [p.strip() for p in condition.split(" and ")]
                is_match = all(results.get(p, False) for p in parts)
            else:
                # Default fallback
                is_match = results.get(condition, False)

            if is_match:
                matched.append(log)
            else:
                unmatched.append(log)

        # False positives: if ground truth provided or benign logs matched
        fps: List[Dict[str, Any]] = []
        if expected_matches is not None:
            # expected_matches are indices of true positives
            for idx, log in enumerate(logs):
                if log in matched and idx not in expected_matches:
                    fps.append(log)
        else:
            # If log has benign flag
            fps = [log for log in matched if log.get("benign") is True or log.get("is_fp") is True]

        return MatchResult(
            rule_title=rule.title,
            matched_lines=matched,
            count=len(matched),
            false_positives=fps,
            total_evaluated=len(logs)
        )
