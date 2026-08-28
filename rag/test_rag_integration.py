"""
CodeSentinel-X
RAG Integration Test

Tests:
1. Security knowledge loading
2. CWE-aware retrieval
3. Vulnerability-aware retrieval
4. Similarity / distance values
5. Mitigation retrieval
6. Secure example retrieval
7. RAG knowledge quality
8. Compatibility with SecurityRAG.retrieve_knowledge()

Run from project root:

    python -m rag.test_rag_integration
"""

from typing import Any, Dict, List

from .rag_engine import SecurityRAG


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES: List[Dict[str, str]] = [
    {
        "vulnerability": "Command Injection",
        "cwe": "CWE-78",
    },
    {
        "vulnerability": "Code Injection",
        "cwe": "CWE-95",
    },
    {
        "vulnerability": "Unsafe Deserialization",
        "cwe": "CWE-502",
    },
    {
        "vulnerability": "Hardcoded Secret",
        "cwe": "CWE-798",
    },
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_cwe(value: Any) -> str:
    """
    Normalize CWE values.

    Examples:
        CWE-78
        cwe-78
        " CWE-78 "
    """

    if value is None:
        return ""

    return str(value).strip().upper()


def normalize_vulnerability(value: Any) -> str:
    """
    Normalize vulnerability names for comparison.
    """

    if value is None:
        return ""

    value = str(value).strip().lower()

    aliases = {
        "command execution": "command injection",
        "os command injection": "command injection",
        "command-injection": "command injection",

        "code-injection": "code injection",

        "hardcoded password": "hardcoded secret",
        "hardcoded_password_string": "hardcoded secret",
        "hardcoded credential": "hardcoded secret",

        "subprocess_without_shell_equals_true":
            "command injection",

        "subprocess_popen_with_shell_equals_true":
            "command injection",
    }

    return aliases.get(value, value)


def get_mitigation(document: Dict[str, Any]) -> List[str]:
    """
    Safely retrieve mitigation information.
    """

    mitigation = document.get("mitigation", [])

    if isinstance(mitigation, list):
        return [
            str(item).strip()
            for item in mitigation
            if str(item).strip()
        ]

    if mitigation:
        return [str(mitigation).strip()]

    return []


def print_separator(char: str = "-", length: int = 60) -> None:
    print(char * length)


# ============================================================
# MAIN TEST
# ============================================================

def main() -> None:

    print()
    print("=" * 60)
    print("       CodeSentinel-X RAG Integration Test")
    print("=" * 60)
    print()

    # --------------------------------------------------------
    # Initialize RAG
    # --------------------------------------------------------

    try:
        rag = SecurityRAG()

    except Exception as exc:
        print()
        print("RAG INITIALIZATION FAILED")
        print(f"Error: {exc}")
        print()
        raise

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    print()

    if not rag.documents:
        raise RuntimeError(
            "RAG loaded zero security documents."
        )

    print(
        f"Security documents loaded: {len(rag.documents)}"
    )

    print()

    # --------------------------------------------------------
    # Display knowledge base
    # --------------------------------------------------------

    print("=" * 60)
    print("SECURITY KNOWLEDGE BASE")
    print("=" * 60)

    for index, document in enumerate(rag.documents, start=1):

        print()
        print(f"Document #{index}")

        print(
            f"CWE          : "
            f"{document.get('cwe')}"
        )

        print(
            f"Vulnerability: "
            f"{document.get('vulnerability')}"
        )

        print(
            f"Title        : "
            f"{document.get('title')}"
        )

        mitigation = get_mitigation(document)

        print(
            f"Mitigations  : "
            f"{len(mitigation)}"
        )

    print()

    # --------------------------------------------------------
    # Verify CWEs exist in knowledge base
    # --------------------------------------------------------

    print("=" * 60)
    print("CWE VALIDATION")
    print("=" * 60)

    knowledge_cwes = {
        normalize_cwe(document.get("cwe"))
        for document in rag.documents
        if document.get("cwe")
    }

    print()
    print(
        "Knowledge Base CWEs:"
    )

    for cwe in sorted(knowledge_cwes):
        print(f"  • {cwe}")

    print()

    expected_cwes = {
        "CWE-78",
        "CWE-95",
        "CWE-502",
        "CWE-798",
    }

    missing_cwes = expected_cwes - knowledge_cwes

    if missing_cwes:

        print(
            "WARNING: Missing expected CWEs:"
        )

        for cwe in sorted(missing_cwes):
            print(f"  • {cwe}")

    else:

        print(
            "PASS: All expected CWEs are present."
        )

    print()

    # --------------------------------------------------------
    # Run retrieval tests
    # --------------------------------------------------------

    total_tests = len(TEST_CASES)

    passed_tests = 0
    cwe_passed = 0
    vulnerability_passed = 0
    mitigation_passed = 0
    secure_example_passed = 0

    # --------------------------------------------------------
    # Individual tests
    # --------------------------------------------------------

    for test_number, test_case in enumerate(
        TEST_CASES,
        start=1
    ):

        vulnerability = test_case["vulnerability"]
        cwe = test_case["cwe"]

        print()
        print("=" * 60)
        print(
            f"Finding: {vulnerability}"
        )
        print(
            f"CWE: {cwe}"
        )
        print("=" * 60)

        # ----------------------------------------------------
        # Use the main RAG retrieval API
        # ----------------------------------------------------

        results = rag.search_by_vulnerability(
            vulnerability=vulnerability,
            cwe_id=cwe,
            top_k=1,
        )

        # ----------------------------------------------------
        # Check result
        # ----------------------------------------------------

        if not results:

            print()
            print("RESULT: FAIL")
            print("No document was retrieved.")

            continue

        retrieved = results[0]

        retrieved_cwe = retrieved.get("cwe")
        retrieved_vulnerability = retrieved.get(
            "vulnerability"
        )

        similarity = retrieved.get(
            "similarity",
            None
        )

        distance = retrieved.get(
            "distance",
            None
        )

        # ----------------------------------------------------
        # Normalize retrieved values
        # ----------------------------------------------------

        retrieved_cwe_normalized = normalize_cwe(
            retrieved_cwe
        )

        expected_cwe_normalized = normalize_cwe(
            cwe
        )

        retrieved_vulnerability_normalized = (
            normalize_vulnerability(
                retrieved_vulnerability
            )
        )

        expected_vulnerability_normalized = (
            normalize_vulnerability(
                vulnerability
            )
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # CWE Match must be based on the actual retrieved
        # document field.
        # ----------------------------------------------------

        cwe_match = (
            retrieved_cwe_normalized
            == expected_cwe_normalized
        )

        vulnerability_match = (
            retrieved_vulnerability_normalized
            == expected_vulnerability_normalized
        )

        # ----------------------------------------------------
        # Print retrieval result
        # ----------------------------------------------------

        print()

        print(
            f"Retrieved CWE       : "
            f"{retrieved_cwe}"
        )

        print(
            f"Retrieved Vulnerability: "
            f"{retrieved_vulnerability}"
        )

        if similarity is not None:
            print(
                f"Similarity          : "
                f"{float(similarity):.4f}"
            )

        if distance is not None:
            print(
                f"Similarity Distance : "
                f"{float(distance):.4f}"
            )

        print(
            f"CWE Match           : "
            f"{'PASS' if cwe_match else 'FAIL'}"
        )

        print(
            f"Vulnerability Match : "
            f"{'PASS' if vulnerability_match else 'FAIL'}"
        )

        # ----------------------------------------------------
        # Count metrics
        # ----------------------------------------------------

        if cwe_match:
            cwe_passed += 1

        if vulnerability_match:
            vulnerability_passed += 1

        # ----------------------------------------------------
        # Mitigation
        # ----------------------------------------------------

        mitigation = get_mitigation(
            retrieved
        )

        if mitigation:

            mitigation_passed += 1

            print()
            print("Mitigation:")

            for item in mitigation:
                print(
                    f"  • {item}"
                )

        else:

            print()
            print(
                "Mitigation: MISSING"
            )

        # ----------------------------------------------------
        # Secure example
        # ----------------------------------------------------

        secure_example = str(
            retrieved.get(
                "secure_example",
                ""
            )
        ).strip()

        if secure_example:

            secure_example_passed += 1

            print()
            print(
                "Secure Example:"
            )

            print(
                secure_example
            )

        else:

            print()
            print(
                "Secure Example: MISSING"
            )

        # ----------------------------------------------------
        # Print complete retrieved knowledge
        # ----------------------------------------------------

        print()
        print(
            "Retrieved Knowledge:"
        )

        print(
            f"CWE: "
            f"{retrieved.get('cwe')}"
        )

        print(
            f"Vulnerability: "
            f"{retrieved.get('vulnerability')}"
        )

        print(
            f"Title: "
            f"{retrieved.get('title')}"
        )

        print(
            f"Description: "
            f"{retrieved.get('description')}"
        )

        print(
            f"Impact: "
            f"{retrieved.get('impact')}"
        )

        common_causes = retrieved.get(
            "common_causes",
            []
        )

        if isinstance(common_causes, list):

            common_causes_text = ", ".join(
                str(x)
                for x in common_causes
            )

        else:

            common_causes_text = str(
                common_causes
            )

        print(
            f"Common Causes: "
            f"{common_causes_text}"
        )

        print(
            f"Mitigation: "
            f"{mitigation}"
        )

        print(
            f"Secure Example: "
            f"{secure_example}"
        )

        # ----------------------------------------------------
        # Overall test result
        # ----------------------------------------------------

        test_passed = (
            cwe_match
            and vulnerability_match
            and bool(mitigation)
            and bool(secure_example)
        )

        print()

        if test_passed:

            print(
                f"TEST #{test_number}: PASS"
            )

            passed_tests += 1

        else:

            print(
                f"TEST #{test_number}: FAIL"
            )

    # ========================================================
    # TEST retrieve_knowledge()
    # ========================================================

    print()
    print("=" * 60)
    print("RETRIEVE_KNOWLEDGE() COMPATIBILITY TEST")
    print("=" * 60)

    compatibility_passed = 0

    for test_case in TEST_CASES:

        vulnerability = test_case["vulnerability"]
        cwe = test_case["cwe"]

        result = rag.retrieve_knowledge(
            vulnerability=vulnerability,
            cwe_id=cwe,
            top_k=1,
        )

        if result is None:

            print(
                f"FAIL: {vulnerability} "
                f"({cwe})"
            )

            continue

        result_cwe = normalize_cwe(
            result.get("cwe")
        )

        if result_cwe == normalize_cwe(cwe):

            print(
                f"PASS: {vulnerability} "
                f"({cwe})"
            )

            compatibility_passed += 1

        else:

            print(
                f"FAIL: {vulnerability} "
                f"expected {cwe}, "
                f"got {result.get('cwe')}"
            )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("RAG TEST SUMMARY")
    print("=" * 60)

    print()

    print(
        f"Documents Loaded       : "
        f"{len(rag.documents)}"
    )

    print(
        f"Retrieval Tests Passed : "
        f"{passed_tests}/{total_tests}"
    )

    print(
        f"CWE Matches            : "
        f"{cwe_passed}/{total_tests}"
    )

    print(
        f"Vulnerability Matches  : "
        f"{vulnerability_passed}/{total_tests}"
    )

    print(
        f"Mitigations Retrieved  : "
        f"{mitigation_passed}/{total_tests}"
    )

    print(
        f"Secure Examples        : "
        f"{secure_example_passed}/{total_tests}"
    )

    print(
        f"Compatibility Tests    : "
        f"{compatibility_passed}/{total_tests}"
    )

    # --------------------------------------------------------
    # Calculate retrieval accuracy
    # --------------------------------------------------------

    retrieval_accuracy = (
        passed_tests / total_tests * 100
        if total_tests
        else 0
    )

    cwe_accuracy = (
        cwe_passed / total_tests * 100
        if total_tests
        else 0
    )

    vulnerability_accuracy = (
        vulnerability_passed
        / total_tests
        * 100
        if total_tests
        else 0
    )

    mitigation_coverage = (
        mitigation_passed
        / total_tests
        * 100
        if total_tests
        else 0
    )

    secure_example_coverage = (
        secure_example_passed
        / total_tests
        * 100
        if total_tests
        else 0
    )

    print()

    print(
        f"Overall Retrieval Accuracy : "
        f"{retrieval_accuracy:.2f}%"
    )

    print(
        f"CWE Retrieval Accuracy     : "
        f"{cwe_accuracy:.2f}%"
    )

    print(
        f"Vulnerability Accuracy     : "
        f"{vulnerability_accuracy:.2f}%"
    )

    print(
        f"Mitigation Coverage        : "
        f"{mitigation_coverage:.2f}%"
    )

    print(
        f"Secure Example Coverage    : "
        f"{secure_example_coverage:.2f}%"
    )

    # ========================================================
    # FINAL STATUS
    # ========================================================

    print()
    print("=" * 60)

    if (
        passed_tests == total_tests
        and compatibility_passed == total_tests
    ):

        print(
            "       RAG INTEGRATION TEST PASSED"
        )

    else:

        print(
            "       RAG INTEGRATION TEST COMPLETED"
        )

        print()
        print(
            "Some RAG quality checks failed."
        )

    print("=" * 60)
    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()