from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from security.unified_scanner import analyze_security
from security.risk_engine import calculate_risk_score
from security.repair_engine import (
    generate_repair,
    generate_repaired_code,
    validate_repair,
)


# ============================================================
# FastAPI Application
# ============================================================

app = FastAPI(
    title="CodeSentinel-X",
    description=(
        "AST-Guided Agentic AI Framework for Software Vulnerability "
        "Detection and Automated Code Repair"
    ),
    version="2.0.0",
)


# ============================================================
# CORS Configuration
# ============================================================

# This configuration is suitable for local development/demo use.
# Before production deployment, restrict allow_origins to the
# actual frontend domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Request Models
# ============================================================

class CodeRequest(BaseModel):
    """
    Request model used for scanning/analyzing source code.
    """

    code: str = Field(..., min_length=1)
    filename: str = "unknown.py"


class RepairRequest(BaseModel):
    """
    Request model used for code repair and closed-loop verification.
    """

    code: str = Field(..., min_length=1)
    findings: Optional[List[Dict[str, Any]]] = None
    filename: str = "unknown.py"


# ============================================================
# Scanner Helper
# ============================================================

def scan_code(
    code: str,
    filename: str = "unknown.py",
) -> List[Dict[str, Any]]:
    """
    Run the existing CodeSentinel-X unified security scanner.
    """

    return analyze_security(code, filename)


# ============================================================
# Finding Enrichment
# ============================================================

def enrich_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Add risk-engine metadata to scanner findings.

    The original scanner finding is preserved, while additional
    fields such as CWE, confidence, risk score and risk level
    are exposed through the API.
    """

    enriched: List[Dict[str, Any]] = []

    for finding in findings:

        risk = calculate_risk_score(finding)

        item = dict(finding)

        # ----------------------------------------------------
        # CWE information
        # ----------------------------------------------------

        item["cwe_id"] = risk["cwe_id"]
        item["cwe_name"] = risk["cwe_name"]

        # ----------------------------------------------------
        # Confidence
        # ----------------------------------------------------

        item["confidence"] = risk["confidence"]

        # ----------------------------------------------------
        # Risk information
        # ----------------------------------------------------

        item["base_score"] = risk["base_score"]
        item["risk_score"] = risk["risk_score"]
        item["risk_level"] = risk["risk_level"]

        # ----------------------------------------------------
        # Normalized severity
        # ----------------------------------------------------

        item["severity"] = risk["severity"]

        enriched.append(item)

    return enriched


# ============================================================
# Scan Response Builder
# ============================================================

def build_scan_response(
    code: str,
    filename: str,
) -> Dict[str, Any]:
    """
    Execute the scanner and construct a frontend-friendly
    security report.
    """

    # Run scanner
    findings = scan_code(code, filename)

    # Add risk/CWE information
    findings = enrich_findings(findings)

    # --------------------------------------------------------
    # Severity summary
    # --------------------------------------------------------

    severity_counts: Dict[str, int] = {}

    # --------------------------------------------------------
    # Risk summary
    # --------------------------------------------------------

    risk_counts: Dict[str, int] = {}

    for finding in findings:

        severity = finding.get(
            "severity",
            "MEDIUM",
        )

        risk_level = finding.get(
            "risk_level",
            "MEDIUM",
        )

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

        risk_counts[risk_level] = (
            risk_counts.get(risk_level, 0) + 1
        )

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {
        "status": "success",
        "filename": filename,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "risk_summary": risk_counts,
        "findings": findings,
    }


# ============================================================
# Root Endpoint
# ============================================================

@app.get("/")
def root():
    """
    Basic project information endpoint.
    """

    return {
        "project": "CodeSentinel-X",
        "status": "running",
        "version": "2.0.0",
        "message": "AI-powered code security platform",
    }


# ============================================================
# Health Endpoints
# ============================================================

@app.get("/health")
@app.get("/api/health")
def health_check():
    """
    Health check endpoint.
    """

    return {
        "status": "healthy",
        "project": "CodeSentinel-X",
        "version": "2.0.0",
    }


# ============================================================
# Analyze Endpoints
# ============================================================

@app.post("/analyze")
@app.post("/api/analyze")
def analyze(
    request: CodeRequest,
):
    """
    Analyze source code for security vulnerabilities.

    This endpoint uses the unified scanner and risk engine.
    """

    return build_scan_response(
        request.code,
        request.filename,
    )


# ============================================================
# Scan Endpoint
# ============================================================

@app.post("/api/scan")
def api_scan(
    request: CodeRequest,
):
    """
    Main Phase 2 scanning endpoint.

    Input:
        Python source code

    Output:
        Vulnerability findings
        CWE information
        Severity
        Risk score
        Risk level
        Summary information
    """

    return build_scan_response(
        request.code,
        request.filename,
    )


# ============================================================
# Repair Endpoint
# ============================================================

@app.post("/api/repair")
def api_repair(
    request: RepairRequest,
):
    """
    Generate deterministic security repairs for detected
    vulnerabilities and validate the resulting code.
    """

    try:

        # ----------------------------------------------------
        # Obtain findings
        # ----------------------------------------------------

        findings = request.findings

        if findings is None:

            findings = scan_code(
                request.code,
                request.filename,
            )

        # ----------------------------------------------------
        # Add risk information
        # ----------------------------------------------------

        findings = enrich_findings(findings)

        # ----------------------------------------------------
        # No vulnerabilities
        # ----------------------------------------------------

        if not findings:

            return {
                "status": "success",
                "repair_status": "NO_FINDINGS",
                "filename": request.filename,
                "original_code": request.code,
                "repaired_code": request.code,
                "repairs": [],
            }

        # ----------------------------------------------------
        # Generate individual repair recommendations
        # ----------------------------------------------------

        repairs: List[Dict[str, Any]] = []

        for finding in findings:

            repair = generate_repair(
                finding=finding,
            )

            repairs.append(
                {
                    "line": finding.get("line"),
                    "vulnerability": finding.get(
                        "vulnerability"
                    ),
                    "cwe_id": finding.get("cwe_id"),
                    **repair,
                }
            )

        # ----------------------------------------------------
        # Generate repaired source code
        # ----------------------------------------------------

        repaired_code = generate_repaired_code(
            request.code,
            findings,
        )

        # ----------------------------------------------------
        # Validate repair
        # ----------------------------------------------------

        validation = validate_repair(
            request.code,
            repaired_code,
        )

        # ----------------------------------------------------
        # Final response
        # ----------------------------------------------------

        return {
            "status": "success",
            "repair_status": "COMPLETED",
            "filename": request.filename,
            "total_findings": len(findings),
            "repairs": repairs,
            "original_code": request.code,
            "repaired_code": repaired_code,
            "validation": validation,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Repair pipeline error: {exc}",
        ) from exc


# ============================================================
# Closed-Loop Verification Endpoint
# ============================================================

@app.post("/api/closed-loop")
def api_closed_loop(
    request: RepairRequest,
):
    """
    Execute the complete CodeSentinel-X closed-loop pipeline:

        1. Scan original code
        2. Detect vulnerabilities
        3. Generate repairs
        4. Validate repaired code
        5. Re-scan repaired code
        6. Calculate security reduction
        7. Determine PASS / REVIEW_REQUIRED
    """

    try:

        # ----------------------------------------------------
        # STEP 1 — Initial scan
        # ----------------------------------------------------

        initial_findings = scan_code(
            request.code,
            request.filename,
        )

        initial_findings = enrich_findings(
            initial_findings
        )

        # ----------------------------------------------------
        # STEP 2 — Code already clean
        # ----------------------------------------------------

        if not initial_findings:

            return {
                "status": "success",
                "closed_loop_status": "PASS",
                "filename": request.filename,
                "initial_findings": [],
                "initial_count": 0,
                "repaired_code": request.code,
                "validation": {
                    "syntax_valid": True,
                    "all_passed": True,
                },
                "remaining_findings": [],
                "remaining_count": 0,
                "security_reduction_percent": 100.0,
            }

        # ----------------------------------------------------
        # STEP 3 — Generate repaired code
        # ----------------------------------------------------

        repaired_code = generate_repaired_code(
            request.code,
            initial_findings,
        )

        # ----------------------------------------------------
        # STEP 4 — Validate repair
        # ----------------------------------------------------

        validation = validate_repair(
            request.code,
            repaired_code,
        )

        # ----------------------------------------------------
        # STEP 5 — Re-scan repaired code
        # ----------------------------------------------------

        remaining_findings = scan_code(
            repaired_code,
            request.filename,
        )

        remaining_findings = enrich_findings(
            remaining_findings
        )

        # ----------------------------------------------------
        # STEP 6 — Calculate security reduction
        # ----------------------------------------------------

        initial_count = len(initial_findings)
        remaining_count = len(remaining_findings)

        if initial_count:

            reduction = round(
                (
                    (
                        initial_count
                        - remaining_count
                    )
                    / initial_count
                )
                * 100,
                2,
            )

        else:

            reduction = 100.0

        # ----------------------------------------------------
        # STEP 7 — Determine closed-loop result
        # ----------------------------------------------------

        closed_loop_pass = (
            validation.get(
                "all_passed",
                False,
            )
            and remaining_count == 0
        )

        # ----------------------------------------------------
        # Final response
        # ----------------------------------------------------

        return {
            "status": "success",
            "closed_loop_status": (
                "PASS"
                if closed_loop_pass
                else "REVIEW_REQUIRED"
            ),
            "filename": request.filename,
            "initial_findings": initial_findings,
            "initial_count": initial_count,
            "repaired_code": repaired_code,
            "validation": validation,
            "remaining_findings": remaining_findings,
            "remaining_count": remaining_count,
            "security_reduction_percent": reduction,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Closed-loop pipeline error: {exc}",
        ) from exc