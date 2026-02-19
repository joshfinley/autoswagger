"""Response analysis: PII detection, secret scanning, and response classification."""

from __future__ import annotations

import json
import logging
import re

import defusedxml.ElementTree as ET
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
from returns.result import safe

from autoswagger.models import PIIFinding, SecretFinding

logger = logging.getLogger("autoswagger")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONTEXT_KEYWORDS: tuple[str, ...] = (
    "name", "email", "phone", "addr", "tel", "contact", "location",
)

PII_ENTITIES: list[str] = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "ADDRESS"]

TRUFFLEHOG_REGEXES: dict[str, str] = {
    "Slack Token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[fF][aA][cC][eE][bB][oO][oO][kK].*['\"]?[0-9a-f]{32}['\"]?",
    "GitHub": r"[gG][iI][tT][hH][uU][bB].*['\"]?[0-9a-zA-Z]{35,40}['\"]?",
    "Generic API Key": r"[aA][pP][iI]_?[kK][eE][yY].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}['\"\s]",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Telegram Bot API Key": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": r"[tT][wW][iI][tT][tT][eE][rR].*['\"]?[0-9a-zA-Z]{35,44}['\"]?",
}

COMPILED_TRUFFLEHOG_REGEXES: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern) for name, pattern in TRUFFLEHOG_REGEXES.items()
}

DEBUG_INFO_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:env\.[A-Za-z_]+|AWS_[A-Z_]+|AZURE_[A-Z_]+|DEBUG|ERROR)\b",
)

# ---------------------------------------------------------------------------
# Presidio setup
# ---------------------------------------------------------------------------


def create_analyzer() -> AnalyzerEngine:
    """Set up Presidio with custom PII recognizers and return the engine."""
    registry = RecognizerRegistry()

    recognizers = [
        PatternRecognizer(
            supported_entity="PERSON",
            patterns=[Pattern("person", r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", 0.85)],
            context=["name", "first_name", "last_name", "firstname", "lastname"],
        ),
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[Pattern("phone_number", r"(\+?\d{1,3}[-.\s]?(\d{3})[-.\s]?(\d{3,4})[-.\s]?(\d{4}))", 0.85)],
            context=["phone", "mobile", "telephone", "tel", "phone_number"],
        ),
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            patterns=[Pattern("email", r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", 0.85)],
            context=["email", "email_address", "contact"],
        ),
        PatternRecognizer(
            supported_entity="ADDRESS",
            patterns=[Pattern("address", r"\b\d{1,5}\s\w+\s\w+\b", 0.85)],
            context=["addr", "address", "location"],
        ),
    ]
    for recognizer in recognizers:
        registry.add_recognizer(recognizer)

    enhancer = LemmaContextAwareEnhancer(
        context_similarity_factor=0.35,
        min_score_with_context_similarity=0.4,
    )
    return AnalyzerEngine(registry=registry, context_aware_enhancer=enhancer)


# Module-level analyzer instance (lazy init to avoid import-time spaCy load)
_analyzer: AnalyzerEngine | None = None


def _get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = create_analyzer()
    return _analyzer


# ---------------------------------------------------------------------------
# PII detection — CSV (flattened from 14 levels to max 3)
# ---------------------------------------------------------------------------


def _parse_csv_header(first_line: str) -> list[str] | None:
    """Parse CSV header. Returns lowercase column names or None if not CSV-like."""
    columns = first_line.split(",")
    if len(columns) < 3:
        return None
    return [col.strip().lower() for col in columns]


def _identify_context_columns(header: list[str]) -> list[int]:
    """Return indices of columns whose names contain a context keyword."""
    indices: list[int] = []
    for i, col_name in enumerate(header):
        if any(kw in col_name for kw in CONTEXT_KEYWORDS):
            indices.append(i)
    return indices


def _run_presidio(text: str, analyzer: AnalyzerEngine) -> list[PIIFinding]:
    """Run Presidio on a single text value and return findings."""
    if not text:
        return []
    results = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    findings: list[PIIFinding] = []
    for entity in results:
        value = text[entity.start:entity.end]
        findings.append(PIIFinding(
            entity_type=entity.entity_type,
            values=(value,),
            detection_method="context",
        ))
    return findings


def _scan_csv_row(
    line: str,
    header: list[str],
    context_columns: list[int],
    analyzer: AnalyzerEngine,
) -> list[PIIFinding]:
    """Scan one CSV row for PII in context-relevant columns."""
    cols = line.split(",")
    if len(cols) != len(header):
        return []
    findings: list[PIIFinding] = []
    for col_idx in context_columns:
        cell = cols[col_idx].strip()
        findings.extend(_run_presidio(cell, analyzer))
    return findings


@safe
def detect_pii_in_csv(content: str, analyzer: AnalyzerEngine) -> list[PIIFinding]:
    """Detect PII in CSV-like content. Max nesting: 3 levels."""
    lines = content.splitlines()
    if not lines:
        return []

    header = _parse_csv_header(lines[0])
    if not header:
        return []

    context_columns = _identify_context_columns(header)
    if not context_columns:
        return []

    findings: list[PIIFinding] = []
    for line in lines[1:]:
        findings.extend(_scan_csv_row(line, header, context_columns, analyzer))
    return findings


# ---------------------------------------------------------------------------
# PII detection — key:value lines (flattened from 13 levels to max 3)
# ---------------------------------------------------------------------------


def _scan_kv_line(line: str, analyzer: AnalyzerEngine) -> list[PIIFinding]:
    """Scan a single 'key: value' line for PII."""
    if ":" not in line:
        return []
    key_part, _, val_part = line.partition(":")
    key_lower = key_part.strip().lower()
    value = val_part.strip()
    if not any(kw in key_lower for kw in CONTEXT_KEYWORDS):
        return []
    return _run_presidio(value, analyzer)


@safe
def detect_pii_in_keyvalue(content: str, analyzer: AnalyzerEngine) -> list[PIIFinding]:
    """Detect PII in key:value formatted content. Max nesting: 2 levels."""
    findings: list[PIIFinding] = []
    for line in content.splitlines():
        findings.extend(_scan_kv_line(line, analyzer))
    return findings


# ---------------------------------------------------------------------------
# Secret detection (TruffleHog regexes — pure, cannot raise)
# ---------------------------------------------------------------------------


def detect_secrets(content: str) -> list[SecretFinding]:
    """Scan content for known secret patterns. Pure function."""
    findings: list[SecretFinding] = []

    for name, pattern in COMPILED_TRUFFLEHOG_REGEXES.items():
        matches = pattern.findall(content)
        if matches:
            # findall may return tuples for groups; flatten to strings
            values = tuple(m if isinstance(m, str) else m[0] for m in matches[:2])
            findings.append(SecretFinding(
                secret_type=name,
                matched_values=values,
                regex_pattern=pattern.pattern,
            ))

    debug_matches = DEBUG_INFO_PATTERN.findall(content)
    if debug_matches:
        findings.append(SecretFinding(
            secret_type="Debug Information",  # nosec B106 - not a password
            matched_values=tuple(debug_matches[:2]),
            regex_pattern=DEBUG_INFO_PATTERN.pattern,
        ))

    return findings


# ---------------------------------------------------------------------------
# Response size classification
# ---------------------------------------------------------------------------

LARGE_RESPONSE_THRESHOLD = 100_000  # bytes
LARGE_ITEM_THRESHOLD = 100


@safe
def classify_response_size(content: str) -> bool:
    """Return True if the response is considered 'large'."""
    if len(content) > LARGE_RESPONSE_THRESHOLD:
        return True

    stripped = content.strip()
    if stripped.startswith(("{", "[")):
        data = json.loads(stripped)
        if isinstance(data, list) and len(data) >= LARGE_ITEM_THRESHOLD:
            return True
        if isinstance(data, dict) and len(data) >= LARGE_ITEM_THRESHOLD:
            return True

    if stripped.startswith("<"):
        root = ET.fromstring(stripped)
        if sum(1 for _ in root.iter()) >= LARGE_ITEM_THRESHOLD:
            return True

    return False


# ---------------------------------------------------------------------------
# Top-level analysis orchestrator
# ---------------------------------------------------------------------------


def _deduplicate_pii(findings: list[PIIFinding]) -> tuple[PIIFinding, ...]:
    """Merge findings by entity_type, keeping up to 2 sample values each."""
    by_type: dict[str, set[str]] = {}
    method_by_type: dict[str, str] = {}
    for f in findings:
        by_type.setdefault(f.entity_type, set()).update(f.values)
        method_by_type.setdefault(f.entity_type, f.detection_method)

    return tuple(
        PIIFinding(
            entity_type=entity_type,
            values=tuple(list(values)[:2]),
            detection_method=method_by_type[entity_type],
        )
        for entity_type, values in by_type.items()
    )


def analyze_response(
    content: str,
) -> tuple[tuple[PIIFinding, ...], tuple[SecretFinding, ...], bool]:
    """
    Full analysis pipeline for a single response body.

    Returns (pii_findings, secret_findings, is_interesting).
    """
    analyzer = _get_analyzer()

    # PII: CSV + key:value scanning
    csv_findings = detect_pii_in_csv(content, analyzer).value_or([])
    kv_findings = detect_pii_in_keyvalue(content, analyzer).value_or([])
    all_pii = _deduplicate_pii(csv_findings + kv_findings)

    # Secrets
    secrets = tuple(detect_secrets(content))

    # Size classification
    is_large = classify_response_size(content).value_or(False)

    is_interesting = bool(all_pii) or bool(secrets) or is_large

    return all_pii, secrets, is_interesting
