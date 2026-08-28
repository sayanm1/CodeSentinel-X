# security/risk_engine.py

"""
CodeSentinel-X Risk Engine

Calculates vulnerability risk scores and preserves
finding metadata such as vulnerability name, CWE,
severity and confidence.
"""

from typing import Any, Dict


# ============================================================
# SEVERITY BASE SCORES
# ============================================================

SEVERITY_BASE = {
    "INFO": 1.0,
    "LOW": 3.0,
    "MEDIUM": 5.0,
    "HIGH": 7.0,
    "CRITICAL": 9.0,
    "WARNING": 5.0,
}


# ============================================================
# SEVERITY NORMALIZATION
# ============================================================

def normalize_severity(severity: Any) -> str:
    """
    Normalize severity into a supported severity category.
    """

    if severity is None:
        return "MEDIUM"

    severity = str(severity).strip().upper()

    # Semgrep commonly reports WARNING.
    if severity == "WARNING":
        return "MEDIUM"

    if severity not in SEVERITY_BASE:
        return "MEDIUM"

    return severity


# ============================================================
# CONFIDENCE NORMALIZATION
# ============================================================

def normalize_confidence(confidence: Any) -> float:
    """
    Convert scanner confidence into a numeric value from 0.0 to 1.0.

    Supported examples:

        HIGH   -> 0.90
        MEDIUM -> 0.75
        LOW    -> 0.50

    Numeric values are also accepted.
    """

    if confidence is None:
        return 1.0

    if isinstance(confidence, str):

        value = confidence.strip().upper()

        confidence_map = {
            "HIGH": 0.90,
            "MEDIUM": 0.75,
            "LOW": 0.50,
            "VERY HIGH": 0.95,
            "VERY LOW": 0.25,
        }

        if value in confidence_map:
            return confidence_map[value]

    try:
        confidence = float(confidence)

    except (TypeError, ValueError):
        return 1.0

    # Handle percentages such as 90.
    if confidence > 1.0:
        confidence = confidence / 100.0

    return max(
        0.0,
        min(1.0, confidence)
    )


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(risk_score: float) -> str:
    """
    Convert numerical risk score into a risk category.
    """

    if risk_score >= 8.0:
        return "CRITICAL"

    if risk_score >= 6.5:
        return "HIGH"

    if risk_score >= 4.0:
        return "MEDIUM"

    if risk_score >= 2.0:
        return "LOW"

    return "INFO"


# ============================================================
# MAIN RISK CALCULATION
# ============================================================

def calculate_risk_score(
    finding: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculate risk score for one normalized or raw finding.

    The returned dictionary preserves important metadata so
    downstream components can use the complete risk result.
    """

    if not isinstance(finding, dict):
        raise TypeError(
            "finding must be a dictionary"
        )

    # --------------------------------------------------------
    # Vulnerability
    # --------------------------------------------------------

    vulnerability = (
        finding.get("vulnerability")
        or finding.get("vulnerability_name")
        or finding.get("type")
        or finding.get("name")
        or "Unknown"
    )

    # --------------------------------------------------------
    # CWE
    # --------------------------------------------------------

    cwe_id = (
        finding.get("cwe_id")
        or finding.get("cwe")
        or finding.get("CWE")
        or "Unknown"
    )

    cwe_name = (
        finding.get("cwe_name")
        or finding.get("CWE Name")
        or "Unknown"
    )

    # --------------------------------------------------------
    # Other metadata
    # --------------------------------------------------------

    line = finding.get(
        "line",
        finding.get("line_number")
    )

    severity = normalize_severity(
        finding.get("severity")
    )

    confidence_value = normalize_confidence(
        finding.get("confidence")
    )

    description = finding.get(
        "description",
        finding.get("message", "")
    )

    source = finding.get(
        "source",
        "UNKNOWN"
    )

    # --------------------------------------------------------
    # Base score
    # --------------------------------------------------------

    base_score = SEVERITY_BASE[
        severity
    ]

    # --------------------------------------------------------
    # Confidence adjustment
    # --------------------------------------------------------

    risk_score = base_score

    if confidence_value >= 0.90:

        risk_score += 0.5

    elif confidence_value >= 0.75:

        risk_score += 0.25

    # --------------------------------------------------------
    # Clamp score to 10
    # --------------------------------------------------------

    risk_score = min(
        10.0,
        round(
            risk_score,
            2
        )
    )

    # --------------------------------------------------------
    # Determine risk level
    # --------------------------------------------------------

    risk_level = get_risk_level(
        risk_score
    )

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {

        # Finding identity
        "vulnerability": vulnerability,

        # CWE information
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,

        # Location
        "line": line,

        # Scanner information
        "severity": severity,
        "confidence": confidence_value,
        "description": description,
        "source": source,

        # Risk information
        "base_score": base_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


# ============================================================
# BACKWARD-COMPATIBLE FUNCTION
# ============================================================

def calculate_risk(
    finding: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Backward-compatible alias for calculate_risk_score().
    """

    return calculate_risk_score(
        finding
    )