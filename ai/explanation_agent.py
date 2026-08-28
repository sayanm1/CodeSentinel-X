from typing import Optional, Dict, Any

from rag.rag_engine import SecurityRAG


class ExplanationAgent:
    """
    CodeSentinel-X AI Security Explanation Agent

    Uses the SecurityRAG knowledge base to generate structured,
    explainable vulnerability reports.

    Supports:
        - scanner findings
        - risk engine results
        - RAG knowledge
        - CWE information
        - mitigation guidance
        - secure examples
    """

    def __init__(self, rag: Optional[SecurityRAG] = None):
        self.rag = rag if rag is not None else SecurityRAG()

    # ============================================================
    # GENERATE EXPLANATION
    # ============================================================

    def generate_explanation(
        self,
        vulnerability: Optional[str] = None,
        cwe_id: Optional[str] = None,
        line_number: Optional[int] = None,
        severity: Optional[str] = None,
        risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        description: Optional[str] = None,
        code: Optional[str] = None,
        finding: Optional[Dict[str, Any]] = None,
        risk_result: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generate a structured AI security explanation.

        Supports:
            1. Direct arguments
            2. Scanner finding dictionary
            3. Risk Engine result dictionary
        """

        # ========================================================
        # 1. READ FINDING DICTIONARY
        # ========================================================

        if finding is not None:

            if not isinstance(finding, dict):
                raise TypeError(
                    "finding must be a dictionary"
                )

            vulnerability = (
                vulnerability
                or finding.get("vulnerability")
                or finding.get("Vulnerability")
                or finding.get("type")
                or finding.get("name")
            )

            cwe_id = (
                cwe_id
                or finding.get("cwe")
                or finding.get("CWE")
                or finding.get("cwe_id")
                or finding.get("CWE_ID")
            )

            line_number = (
                line_number
                if line_number is not None
                else (
                    finding.get("line")
                    or finding.get("line_number")
                )
            )

            severity = (
                severity
                or finding.get("severity")
                or finding.get("Severity")
            )

            description = (
                description
                or finding.get("description")
                or finding.get("message")
                or finding.get("reason")
            )

            code = (
                code
                or finding.get("code")
                or finding.get("source_code")
            )

            # ----------------------------------------------------
            # If risk information already exists inside finding
            # ----------------------------------------------------

            if risk_score is None:
                risk_score = finding.get(
                    "risk_score"
                )

            if risk_level is None:
                risk_level = finding.get(
                    "risk_level"
                )

        # ========================================================
        # 2. READ RISK ENGINE RESULT
        # ========================================================

        if risk_result is not None:

            if not isinstance(risk_result, dict):
                raise TypeError(
                    "risk_result must be a dictionary"
                )

            # Risk Engine has priority over missing finding data.
            # This is important because the risk engine calculates
            # the final score separately from the scanner.

            if risk_result.get("risk_score") is not None:
                risk_score = risk_result.get(
                    "risk_score"
                )

            if risk_result.get("risk_level") is not None:
                risk_level = risk_result.get(
                    "risk_level"
                )

            if severity is None:
                severity = risk_result.get(
                    "severity"
                )

        # ========================================================
        # 3. NORMALIZE VULNERABILITY
        # ========================================================

        vulnerability = (
            str(vulnerability).strip()
            if vulnerability
            else "Unknown Vulnerability"
        )

        # ========================================================
        # 4. NORMALIZE CWE
        # ========================================================

        cwe_id = (
            str(cwe_id).strip().upper()
            if cwe_id
            else None
        )

        # ========================================================
        # 5. NORMALIZE SEVERITY
        # ========================================================

        severity = (
            str(severity).strip().upper()
            if severity
            else "UNKNOWN"
        )

        # ========================================================
        # 6. NORMALIZE RISK SCORE
        # ========================================================

        if risk_score is not None:

            try:
                risk_score = float(risk_score)

                # Keep score inside expected 0-10 range
                risk_score = max(
                    0.0,
                    min(10.0, risk_score)
                )

                risk_score = round(
                    risk_score,
                    2
                )

            except (
                TypeError,
                ValueError
            ):
                risk_score = None

        # ========================================================
        # 7. NORMALIZE RISK LEVEL
        # ========================================================

        if risk_level:

            risk_level = (
                str(risk_level)
                .strip()
                .upper()
            )

        else:

            # If risk engine didn't provide a level,
            # fall back to severity.

            risk_level = severity

        # ========================================================
        # 8. RETRIEVE RAG KNOWLEDGE
        # ========================================================

        knowledge = self.rag.retrieve_knowledge(
            vulnerability=vulnerability,
            cwe_id=cwe_id,
            top_k=1,
        )

        # ========================================================
        # 9. FALLBACK KNOWLEDGE
        # ========================================================

        if knowledge is None:

            knowledge = {
                "cwe": cwe_id,
                "vulnerability": vulnerability,
                "title": vulnerability,
                "description": "",
                "impact": "",
                "common_causes": [],
                "mitigation": [],
                "secure_example": "",
                "similarity": 0.0,
                "distance": 1.0,
            }

        # ========================================================
        # 10. EXTRACT RAG INFORMATION
        # ========================================================

        retrieved_cwe = knowledge.get(
            "cwe"
        )

        retrieved_vulnerability = knowledge.get(
            "vulnerability"
        )

        mitigation = knowledge.get(
            "mitigation",
            []
        )

        if mitigation is None:
            mitigation = []

        if not isinstance(
            mitigation,
            list
        ):
            mitigation = [
                str(mitigation)
            ]

        secure_example = knowledge.get(
            "secure_example",
            ""
        )

        # ========================================================
        # 11. LINE INFORMATION
        # ========================================================

        line_text = (
            f" at line {line_number}"
            if line_number is not None
            else ""
        )

        # ========================================================
        # 12. CWE INFORMATION
        # ========================================================

        cwe_text = (
            f"The associated weakness is {cwe_id}."
            if cwe_id
            else "No CWE identifier was provided."
        )

        # ========================================================
        # 13. ISSUE DESCRIPTION
        # ========================================================

        issue_text = (
            f"The detected issue is: {description}."
            if description
            else (
                f"The scanner identified "
                f"{vulnerability}."
            )
        )

        # Avoid accidental double periods
        issue_text = issue_text.replace(
            "..",
            "."
        )

        # ========================================================
        # 14. MAIN EXPLANATION
        # ========================================================

        explanation_text = (
            f"A {vulnerability} vulnerability was detected"
            f"{line_text}. "
            f"{cwe_text} "
            f"{issue_text}"
        )

        # ========================================================
        # 15. WHY DANGEROUS
        # ========================================================

        why_dangerous = knowledge.get(
            "impact",
            ""
        )

        if not why_dangerous:

            why_dangerous = (
                "This vulnerability may allow "
                "attackers to perform unauthorized "
                "actions depending on the affected "
                "application and execution context."
            )

        # ========================================================
        # 16. RAG SIMILARITY
        # ========================================================

        rag_similarity = knowledge.get(
            "similarity",
            0.0
        )

        rag_distance = knowledge.get(
            "distance",
            1.0
        )

        # ========================================================
        # 17. RAG STATUS
        # ========================================================

        rag_retrieved = (
            knowledge is not None
        )

        # ========================================================
        # 18. RETURN FINAL STRUCTURED RESULT
        # ========================================================

        return {

            # ----------------------------------------------------
            # Vulnerability information
            # ----------------------------------------------------

            "vulnerability":
                vulnerability,

            "cwe":
                cwe_id or retrieved_cwe,

            "line":
                line_number,

            "severity":
                severity,

            # ----------------------------------------------------
            # Risk Engine information
            # ----------------------------------------------------

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            # ----------------------------------------------------
            # AI explanation
            # ----------------------------------------------------

            "explanation":
                explanation_text,

            "why_dangerous":
                why_dangerous,

            # ----------------------------------------------------
            # RAG mitigation
            # ----------------------------------------------------

            "mitigation":
                mitigation,

            "secure_example":
                secure_example,

            # ----------------------------------------------------
            # RAG metadata
            # ----------------------------------------------------

            "rag_knowledge_used": {

                "cwe":
                    retrieved_cwe,

                "vulnerability":
                    retrieved_vulnerability,

                "title":
                    knowledge.get("title"),

                "similarity":
                    rag_similarity,

                "distance":
                    rag_distance,
            },

            "rag_similarity":
                rag_similarity,

            "rag_distance":
                rag_distance,

            "rag_retrieved":
                rag_retrieved,

            "knowledge":
                knowledge,
        }


# ================================================================
# FACTORY FUNCTION
# ================================================================

def create_explanation_agent(
    rag: Optional[SecurityRAG] = None,
) -> ExplanationAgent:
    """
    Factory function used by the unified security pipeline.
    """

    if rag is None:
        rag = SecurityRAG()

    return ExplanationAgent(
        rag=rag
    )


# ================================================================
# BACKWARD COMPATIBILITY
# ================================================================

SecurityExplanationAgent = ExplanationAgent