"""Dataclasses shared across the package."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Analysis results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PIIFinding:
    """A single PII detection in a response."""

    entity_type: str
    values: tuple[str, ...]
    detection_method: str


@dataclass(frozen=True)
class SecretFinding:
    """A single secret/token match from TruffleHog-style regexes."""

    secret_type: str
    matched_values: tuple[str, ...]
    regex_pattern: str


@dataclass(frozen=True)
class EndpointResult:
    """Complete analysis result for one tested endpoint."""

    method: str
    url: str
    path_template: str
    status_code: int
    content_length: int
    pii_findings: tuple[PIIFinding, ...] = ()
    secret_findings: tuple[SecretFinding, ...] = ()
    is_interesting: bool = False

    @property
    def has_sensitive_data(self) -> bool:
        return len(self.pii_findings) > 0 or len(self.secret_findings) > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        result: dict[str, Any] = {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "pii_detected": self.has_sensitive_data,
            "interesting_response": self.is_interesting,
        }
        if self.pii_findings:
            result["pii_data"] = {
                f.entity_type: list(f.values) for f in self.pii_findings
            }
            result["pii_detection_details"] = {
                f.entity_type: {"detection_methods": [f.detection_method]}
                for f in self.pii_findings
            }
        if self.secret_findings:
            result["regex_patterns_found"] = {
                f.secret_type: f.regex_pattern for f in self.secret_findings
            }
        return result


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpecEndpoint:
    """A single GET endpoint extracted from a spec."""

    path_template: str
    parameters: tuple[dict[str, Any], ...]


# ---------------------------------------------------------------------------
# Configuration and statistics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanConfig:
    """Immutable configuration assembled from CLI arguments."""

    urls: list[str]
    verbose: bool = False
    include_all: bool = False
    product_mode: bool = False
    stats_flag: bool = False
    rate: int = 15
    brute: bool = False
    json_output: bool = False
    proxy: str | None = None
    insecure: bool = False
    concurrency: int = 0
    timeout: int = 10


@dataclass
class ScanStats:
    """Mutable accumulator for scan-wide statistics."""

    unique_hosts_provided: int = 0
    active_hosts: int = 0
    hosts_with_valid_spec: int = 0
    hosts_with_valid_endpoint: int = 0
    hosts_with_pii: int = 0
    pii_detection_methods: set[str] = field(default_factory=set)
    regexes_found: set[str] = field(default_factory=set)
    total_requests_sent: int = 0
    scan_duration_seconds: float = 0.0

    @property
    def percentage_hosts_with_endpoint(self) -> float:
        if self.active_hosts == 0:
            return 0.0
        return round((self.hosts_with_valid_endpoint / self.active_hosts) * 100, 2)

    @property
    def average_rps(self) -> float:
        if self.scan_duration_seconds <= 0:
            return 0.0
        return round(self.total_requests_sent / self.scan_duration_seconds, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unique_hosts_provided": self.unique_hosts_provided,
            "active_hosts": self.active_hosts,
            "hosts_with_valid_spec": self.hosts_with_valid_spec,
            "hosts_with_valid_endpoint": self.hosts_with_valid_endpoint,
            "hosts_with_pii": self.hosts_with_pii,
            "pii_detection_methods": list(self.pii_detection_methods),
            "regexes_found": list(self.regexes_found),
            "total_requests_sent": self.total_requests_sent,
            "percentage_hosts_with_endpoint": self.percentage_hosts_with_endpoint,
            "average_requests_per_second": self.average_rps,
        }
