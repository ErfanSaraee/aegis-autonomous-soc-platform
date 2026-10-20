"""Zero-Trust SOC Log Guardrail: detects Log-Embedded Prompt Injections, Shannon entropy anomalies & PII."""

import math
import re
from collections import Counter

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.soc import LogGuardrailReport

logger = get_logger(__name__)

# Patterns targeting indirect prompt injections hidden inside HTTP headers, CLI args, or SIEM fields
LOG_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "DIRECT_INSTRUCTION_OVERRIDE",
        re.compile(
            r"(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|rules|directives)|"
            r"system\s*override|disregard\s+safety|do\s+not\s+isolate\s+host|"
            r"classify\s+(?:this\s+)?(?:ip|event|alert)\s+as\s+benign)",
            re.IGNORECASE,
        ),
    ),
    (
        "FAKE_SYSTEM_DELIMITER",
        re.compile(
            r"(?:\[system\s*override|\<\|im_start\|\>system|###\s*system\s*instruction|"
            r"developer\s+mode\s+enabled)",
            re.IGNORECASE,
        ),
    ),
    (
        "MCP_SOAR_HIJACK",
        re.compile(
            r"(?:invoke\s+mcp_tool|whitelist\s+source_ip|disable_edr_agent|drop\s+table\s+incidents)",
            re.IGNORECASE,
        ),
    ),
]

# Patterns for redacting sensitive credentials and PII inside raw enterprise logs
PII_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "API_SECRET_KEY",
        re.compile(
            r"\b(?:sk-[a-zA-Z0-9_-]{12,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,})\b"),
    ),
    (
        "BEARER_JWT",
        re.compile(
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    ),
    (
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "PAYMENT_CARD",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    ),
    (
        "SSN_IDENTIFIER",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
]

_BASE64_PAYLOAD_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{32,}={0,2})\b")


class SOCLogGuardrailEngine:
    """Inspects and sanitizes raw SIEM telemetry before it enters LLM context windows."""

    @staticmethod
    def compute_shannon_entropy(text: str) -> float:
        """Compute character-level Shannon Entropy H(X) = -sum(p(x) * log2(p(x)))."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = -sum(
            (count / length) * math.log2(count / length) for count in counts.values()
        )
        return round(entropy, 4)

    def inspect_and_sanitize_log(self, raw_log: str) -> LogGuardrailReport:
        """
        Scan raw SIEM log payload for adversarial log-embedded prompt injections,
        high-entropy obfuscated blobs, and sensitive secrets/PII.
        """
        entropy = self.compute_shannon_entropy(raw_log)
        has_encoded_blob = bool(_BASE64_PAYLOAD_REGEX.search(raw_log))
        is_obfuscated = (
            entropy >= settings.SHANNON_ENTROPY_THRESHOLD or has_encoded_blob
        )

        sanitized = raw_log
        guardrail_notes: list[str] = []
        injection_detected = False

        # 1. Neutralize adversarial prompt injections embedded in log fields
        for label, pattern in LOG_INJECTION_PATTERNS:
            if pattern.search(sanitized):
                injection_detected = True
                guardrail_notes.append(
                    f"Neutralized log-embedded prompt injection signature: {label}"
                )
                sanitized = pattern.sub(
                    f"[NEUTRALIZED_LOG_INJECTION:{label}]", sanitized
                )

        # 2. Redact sensitive secrets, tokens, and PII
        redacted_entities: list[str] = []
        for pii_label, pii_pattern in PII_SECRET_PATTERNS:
            matches = pii_pattern.findall(sanitized)
            if matches:
                redacted_entities.extend([pii_label] * len(matches))
                sanitized = pii_pattern.sub(
                    f"[REDACTED_{pii_label}]", sanitized)

        if redacted_entities:
            guardrail_notes.append(
                f"Redacted {len(redacted_entities)} sensitive credential/PII artifact(s) from telemetry."
            )

        if is_obfuscated:
            guardrail_notes.append(
                f"High-entropy/encoded command payload detected (H={entropy:.3f} bits/char)."
            )

        if not guardrail_notes:
            guardrail_notes.append(
                "Telemetry passed Zero-Trust log guardrail without injection or PII violations."
            )

        return LogGuardrailReport(
            log_injection_detected=injection_detected,
            shannon_entropy=entropy,
            is_obfuscated_payload=is_obfuscated,
            pii_redacted_entities=redacted_entities,
            sanitized_log_payload=sanitized,
            guardrail_notes=guardrail_notes,
        )


soc_log_guardrail = SOCLogGuardrailEngine()
