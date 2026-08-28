# security/test_risk_engine.py

"""
CodeSentinel-X Risk Engine Test

Tests the Risk Engine together with the Finding Normalizer so that
CWE information is preserved in the risk results.

Run from project root:

    python -m security.test_risk_engine
"""

from security.risk_engine import calculate_risk_score
from security.finding_normalizer import normalize_finding


# ============================================================
# TEST FINDINGS
# ============================================================

TEST_FINDINGS = [
    {
        "vulnerability": "Code Injection",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Use of eval() can execute attacker-controlled code.",
        "line": 15,
        "source": "AST",
    },

    {
        "vulnerability": "Unsafe Deserialization",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "pickle can execute arbitrary code when loading untrusted data.",
        "line": 17,
        "source": "AST",
    },

    {
        "vulnerability": "Hardcoded Secret",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Possible hardcoded sensitive value stored in password.",
        "line": 6,
        "source": "AST",
    },

    {
        "vulnerability": "Command Injection",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "subprocess.call() uses shell=True.",
        "line": 10,
        "source": "AST",
    },
]


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("       CodeSentinel-X Risk Engine")
    print("=" * 60)

    results = []

    # --------------------------------------------------------
    # Process findings
    # --------------------------------------------------------

    for finding in TEST_FINDINGS:

        # First normalize the finding.
        normalized = normalize_finding(
            finding
        )

        # Then calculate risk.
        result = calculate_risk_score(
            normalized
        )

        results.append(
            result
        )

        print("\nVulnerability:")
        print(
            result.get(
                "vulnerability",
                "Unknown"
            )
        )

        print(
            "CWE:",
            result.get(
                "cwe_id",
                "Unknown"
            )
        )

        print(
            "CWE Name:",
            result.get(
                "cwe_name",
                "Unknown"
            )
        )

        print(
            "Risk Score:",
            result.get(
                "risk_score"
            )
        )

        print(
            "Risk Level:",
            result.get(
                "risk_level"
            )
        )

    # ========================================================
    # VALIDATION
    # ========================================================

    print("\n" + "=" * 60)
    print("             RISK ENGINE VALIDATION")
    print("=" * 60)

    expected_cwes = {
        "Code Injection": "CWE-95",
        "Unsafe Deserialization": "CWE-502",
        "Hardcoded Secret": "CWE-798",
        "Command Injection": "CWE-78",
    }

    passed = 0

    for result in results:

        vulnerability = result.get(
            "vulnerability"
        )

        expected_cwe = expected_cwes.get(
            vulnerability
        )

        actual_cwe = result.get(
            "cwe_id"
        )

        if actual_cwe == expected_cwe:

            print(
                f"PASS: {vulnerability} "
                f"→ {actual_cwe}"
            )

            passed += 1

        else:

            print(
                f"FAIL: {vulnerability} "
                f"→ expected {expected_cwe}, "
                f"got {actual_cwe}"
            )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("             RISK ENGINE TEST SUMMARY")
    print("=" * 60)

    print(
        f"\nCWE Mapping Tests : "
        f"{passed}/{len(results)}"
    )

    if passed == len(results):

        print(
            "\nOverall Result: PASS"
        )

        print(
            "Risk Engine and CWE mapping "
            "are working correctly."
        )

    else:

        print(
            "\nOverall Result: FAIL"
        )

    print("\n" + "=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()