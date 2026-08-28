"""
CodeSentinel-X Finding Normalizer

Normalizes findings from AST, Bandit and Semgrep into one
consistent structure while preserving CWE information.
"""

from typing import Any, Dict, List


VULNERABILITY_CWE_MAP = {
    "command injection": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
    },
    "code injection": {
        "cwe_id": "CWE-95",
        "cwe_name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
    },
    "unsafe deserialization": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
    },
    "hardcoded secret": {
        "cwe_id": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
    },
    "start_process_with_a_shell": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
    },
    "start process with a shell": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
    },
}


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _get_vulnerability_name(finding: Dict[str, Any]) -> str:
    value = (
        finding.get("vulnerability")
        or finding.get("vulnerability_name")
        or finding.get("type")
        or finding.get("name")
        or "Unknown"
    )

    return _normalize_text(value)


def _resolve_cwe(finding: Dict[str, Any]):
    """
    Resolve CWE in this order:

    1. Existing cwe_id
    2. Existing CWE field
    3. Vulnerability name mapping
    """

    cwe_id = (
        finding.get("cwe_id")
        or finding.get("cwe")
        or finding.get("CWE")
    )

    cwe_name = (
        finding.get("cwe_name")
        or finding.get("CWE Name")
    )

    if cwe_id:
        cwe_id = _normalize_text(cwe_id)

        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        return cwe_id, cwe_name

    vulnerability = _get_vulnerability_name(finding).lower()

    mapping = VULNERABILITY_CWE_MAP.get(vulnerability)

    if mapping:
        return mapping["cwe_id"], mapping["cwe_name"]

    return "Unknown", "Unknown"


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize one security finding.
    """

    vulnerability = _get_vulnerability_name(finding)

    cwe_id, cwe_name = _resolve_cwe(finding)

    normalized = {
        "line": finding.get(
            "line",
            finding.get("line_number", 0)
        ),

        "vulnerability": vulnerability,

        "severity": _normalize_text(
            finding.get("severity", "UNKNOWN")
        ).upper(),

        "confidence": _normalize_text(
            finding.get("confidence", "UNKNOWN")
        ).upper(),

        "description": _normalize_text(
            finding.get(
                "description",
                finding.get("message", "")
            )
        ),

        "source": _normalize_text(
            finding.get("source", "UNKNOWN")
        ),

        "cwe_id": cwe_id,

        "cwe_name": cwe_name or "Unknown",
    }

    # Preserve additional information if present.
    for key in [
        "code",
        "filename",
        "file",
        "column",
        "rule_id",
        "test_id",
        "metadata",
    ]:
        if key in finding:
            normalized[key] = finding[key]

    return normalized


def _finding_key(finding: Dict[str, Any]):
    """
    Create a stable key for duplicate detection.

    We deliberately include line + vulnerability + CWE + description
    so different findings on different lines are not accidentally
    merged.
    """

    return (
        finding.get("line"),
        str(finding.get("vulnerability", "")).lower().strip(),
        str(finding.get("cwe_id", "")).upper().strip(),
        str(finding.get("description", "")).lower().strip(),
    )


def normalize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize all findings and remove exact duplicates.
    """

    normalized = []

    seen = set()

    for finding in findings:
        item = normalize_finding(finding)

        key = _finding_key(item)

        if key in seen:
            continue

        seen.add(key)

        normalized.append(item)

    return normalized