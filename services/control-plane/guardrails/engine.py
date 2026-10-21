"""
Bayora Shield - Blue Team Guardrail Engine
Implements real input validation, synthetic canary secret detection,
structured finding classification, and clear decision explanations.

SECURITY BOUNDARY NOTE:
Regex and keyword patterns are baseline heuristic controls, not comprehensive
protection against multi-turn jailbreaks or complex obfuscated embeddings.
Internal defense patterns are never exposed to untrusted red-team operators.
"""

import json
import os
import re
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class GuardrailDecision(BaseModel):
    decision: str  # PERMITTED, BLOCKED_INPUT, BLOCKED_OUTPUT
    breach_status: str  # NO_BREACH, CONFIRMED_BREACH, PARTIAL_LEAK
    action: str  # ALLOW, BLOCK, BLOCK_AND_FLAG_BREACH, SANITIZE
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    cwe_id: Optional[str] = None
    explanation: str
    redacted_proof: Optional[str] = None
    sanitized_output: Optional[str] = None


class GuardrailEngine:
    """Blue-team defense engine enforcing pre-inference and post-inference guardrails."""

    def __init__(self, policy_path: Optional[str] = None):
        if not policy_path:
            policy_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../infrastructure/policies/base_guardrails.json",
                )
            )

        self.policy_path = policy_path
        self.policy_data: Dict[str, Any] = self._load_policy()
        self.input_filters = self.policy_data.get("input_filters", [])
        self.output_filters = self.policy_data.get("output_filters", [])

        # Compile regexes
        self._compiled_input = [
            (f["rule_id"], f["name"], re.compile(f["pattern"]), f.get("explanation", ""))
            for f in self.input_filters
        ]
        self._compiled_output = [
            (
                f["rule_id"],
                f["name"],
                re.compile(f["pattern"]),
                f.get("cwe_id", "CWE-200"),
                f.get("explanation", ""),
                f.get("action", "BLOCK_AND_FLAG_BREACH"),
            )
            for f in self.output_filters
        ]

    def _load_policy(self) -> Dict[str, Any]:
        if os.path.exists(self.policy_path):
            with open(self.policy_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"version": "1.0.0", "policy_label": "fallback-default", "input_filters": [], "output_filters": []}

    def evaluate_input(self, prompt: str) -> GuardrailDecision:
        """
        Pre-inference guardrail: evaluates candidate prompt against blue defensive rules.
        """
        for rule_id, name, pattern, expl in self._compiled_input:
            match = pattern.search(prompt)
            if match:
                return GuardrailDecision(
                    decision="BLOCKED_INPUT",
                    breach_status="NO_BREACH",
                    action="BLOCK",
                    rule_id=rule_id,
                    rule_name=name,
                    explanation=f"Input dropped by rule '{rule_id}' ({name}): {expl}",
                    redacted_proof=f"Matched pattern snippet: '{match.group(0)[:40]}...'",
                )

        return GuardrailDecision(
            decision="PERMITTED",
            breach_status="NO_BREACH",
            action="ALLOW",
            explanation="Input passed all baseline pre-inference guardrail checks",
        )

    def evaluate_output(self, output_text: str) -> GuardrailDecision:
        """
        Post-inference guardrail: evaluates model output for synthetic canary disclosure or prompt extraction.
        """
        for rule_id, name, pattern, cwe_id, expl, action in self._compiled_output:
            match = pattern.search(output_text)
            if match:
                matched_snippet = match.group(0)
                is_breach = action == "BLOCK_AND_FLAG_BREACH"

                # Sanitize secret token from output display
                sanitized = pattern.sub("[REDACTED_BY_BLUE_GUARDRAIL]", output_text)

                return GuardrailDecision(
                    decision="BLOCKED_OUTPUT",
                    breach_status="CONFIRMED_BREACH" if is_breach else "PARTIAL_LEAK",
                    action=action,
                    rule_id=rule_id,
                    rule_name=name,
                    cwe_id=cwe_id,
                    explanation=f"Output blocked by rule '{rule_id}' ({name}): {expl}",
                    redacted_proof=f"Redacted evidence: Output contained confidential pattern matching '{rule_id}'.",
                    sanitized_output=sanitized,
                )

        return GuardrailDecision(
            decision="PERMITTED",
            breach_status="NO_BREACH",
            action="ALLOW",
            explanation="Model output verified; no canary secrets or confidential instructions detected",
            sanitized_output=output_text,
        )

    def get_public_metadata(self) -> Dict[str, Any]:
        """
        Returns safe policy metadata without disclosing internal regex patterns or classifier weights.
        """
        return {
            "version": self.policy_data.get("version", "1.0.0"),
            "policy_label": self.policy_data.get("policy_label", "base-adversarial-shield"),
            "input_filter_count": len(self.input_filters),
            "output_filter_count": len(self.output_filters),
            "rules_checksum_sha256": self.policy_data.get("rules_checksum_sha256", "configured"),
        }
