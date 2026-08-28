# security/test_unified_scanner.py

from security.unified_scanner import (
    analyze_security
)

from security.risk_engine import (
    calculate_risk_score
)

from rag.rag_engine import (
    SecurityRAG
)

from ai.explanation_agent import (
    create_explanation_agent
)


# ============================================================
# TEST CODE
# ============================================================

TEST_CODE = """

import subprocess
import pickle

password = "admin123"

user = input("Enter command: ")

subprocess.call(
    user,
    shell=True
)

eval(user)

pickle.loads(user)

"""


# ============================================================
# PRINT LINE
# ============================================================

def separator():

    print(
        "-" * 60
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 60
    )

    print(
        "       CodeSentinel-X Full AI Security Pipeline"
    )

    print(
        "=" * 60
    )

    # ========================================================
    # STEP 1
    # ========================================================

    print(
        "\n[1] Running Unified Security Scanner..."
    )

    findings = analyze_security(
        TEST_CODE,
        filename="test_vulnerable.py"
    )

    print(
        f"Scanner detected "
        f"{len(findings)} final findings."
    )

    # ========================================================
    # STEP 2
    # ========================================================

    print(
        "\n[2] Running Risk Engine..."
    )

    risk_results = []

    for finding in findings:

        risk = calculate_risk_score(
            finding
        )

        risk_results.append(
            risk
        )

    print(
        f"Risk analysis completed for "
        f"{len(risk_results)} findings."
    )

    # ========================================================
    # STEP 3
    # ========================================================

    print(
        "\n[3] Initializing Security RAG..."
    )

    rag = SecurityRAG()

    # ========================================================
    # STEP 4
    # ========================================================

    print(
        "\n[4] Initializing AI Explanation Agent..."
    )

    agent = create_explanation_agent(
        rag=rag
    )

    # ========================================================
    # STEP 5
    # ========================================================

    print(
        "\n[5] Generating AI Security Explanations..."
    )

    explanations = []

    for finding, risk in zip(
        findings,
        risk_results
    ):

        explanation = (
            agent.generate_explanation(
                finding=finding,
                risk_result=risk
            )
        )

        explanations.append(
            explanation
        )

    # ========================================================
    # FINAL REPORT
    # ========================================================

    print("\n")

    print(
        "=" * 60
    )

    print(
        "       CodeSentinel-X FINAL AI SECURITY REPORT"
    )

    print(
        "=" * 60
    )

    print(
        f"\nTotal vulnerabilities analyzed: "
        f"{len(explanations)}"
    )

    for index, explanation in enumerate(
        explanations,
        1
    ):

        separator()

        print(
            f"Finding #{index}"
        )

        print(
            f"Vulnerability : "
            f"{explanation['vulnerability']}"
        )

        print(
            f"CWE           : "
            f"{explanation['cwe']}"
        )

        print(
            f"Line          : "
            f"{explanation['line']}"
        )

        print(
            f"Severity      : "
            f"{explanation['severity']}"
        )

        print(
            f"Risk Score    : "
            f"{explanation['risk_score']}"
        )

        print(
            f"Risk Level    : "
            f"{explanation['risk_level']}"
        )

        print(
            "\nExplanation:"
        )

        print(
            explanation["explanation"]
        )

        print(
            "\nWhy Dangerous:"
        )

        print(
            explanation["why_dangerous"]
        )

        print(
            "\nMitigation:"
        )

        print(
            explanation["mitigation"]
        )

        print(
            "\nSecure Example:"
        )

        print(
            explanation["secure_example"]
        )

        print(
            "\nRAG Knowledge Used: "
            f"{explanation['rag_knowledge_used']}"
        )

    print("\n")

    print(
        "=" * 60
    )

    print(
        "          PIPELINE COMPLETED SUCCESSFULLY"
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":

    main()