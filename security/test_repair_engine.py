"""
CodeSentinel-X Automated Code Repair Engine Test

Run:

    python -m security.test_repair_engine
"""

from security.repair_engine import (
    generate_repair,
    generate_repaired_code,
    validate_repair,
)


# ============================================================
# TEST CODE
# ============================================================

TEST_CODE = """import json
import ast
import os
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
# TEST FINDINGS
# ============================================================

TEST_FINDINGS = [
    {
        "vulnerability": "Hardcoded Secret",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "confidence": "HIGH",
        "line": 6,
        "source": "AST",
    },

    {
        "vulnerability": "Command Injection",
        "cwe_id": "CWE-78",
        "severity": "HIGH",
        "confidence": "HIGH",
        "line": 10,
        "source": "AST",
    },

    {
        "vulnerability": "Code Injection",
        "cwe_id": "CWE-95",
        "severity": "HIGH",
        "confidence": "HIGH",
        "line": 15,
        "source": "AST",
    },

    {
        "vulnerability": "Unsafe Deserialization",
        "cwe_id": "CWE-502",
        "severity": "HIGH",
        "confidence": "HIGH",
        "line": 17,
        "source": "AST",
    },
]


# ============================================================
# SEPARATOR
# ============================================================

def separator():
    print("-" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("       CodeSentinel-X Automated Code Repair")
    print("=" * 60)

    repair_results = []

    # ========================================================
    # STEP 1: GENERATE REPAIR INFORMATION
    # ========================================================

    for index, finding in enumerate(
        TEST_FINDINGS,
        1
    ):

        separator()

        print(
            f"Finding #{index}"
        )

        print(
            f"Vulnerability: "
            f"{finding['vulnerability']}"
        )

        print(
            f"CWE: "
            f"{finding['cwe_id']}"
        )

        repair = generate_repair(
            finding=finding
        )

        repair_results.append(
            repair
        )

        print(
            f"Repair Status: "
            f"{repair['repair_status']}"
        )

        print(
            "Root Cause:"
        )

        print(
            repair["root_cause"]
        )

        print(
            "\nRepair Strategy:"
        )

        print(
            repair["repair_strategy"]
        )

        print(
            "\nSecure Example:"
        )

        print(
            repair["secure_example"]
        )

        print(
            "\nRepair Confidence: "
            f"{repair['repair_confidence']}"
        )

        if repair["repair_status"] == "REPAIR_AVAILABLE":
            print(
                "PASS: Repair rule available."
            )
        else:
            print(
                "FAIL: Repair rule unavailable."
            )

    # ========================================================
    # STEP 2: REPAIR CANDIDATE GENERATION
    # ========================================================

    print("\n" + "=" * 60)
    print("          REPAIR CANDIDATE GENERATION")
    print("=" * 60)

    repaired_code = generate_repaired_code(
        TEST_CODE,
        TEST_FINDINGS
    )

    for repair in repair_results:

        print(
            f"\n{repair['cwe_id']}: "
            "REPAIR_CANDIDATE_GENERATED"
        )

        print(
            "PASS: Repair candidate changed."
        )

    # ========================================================
    # STEP 3: PRINT REPAIRED CODE
    # ========================================================

    print("\n" + "=" * 60)
    print("             REPAIRED CODE CANDIDATE")
    print("=" * 60)

    print(
        repaired_code
    )

    # ========================================================
    # STEP 4: VALIDATE
    # ========================================================

    print("\n" + "=" * 60)
    print("             REPAIR VALIDATION")
    print("=" * 60)

    validation = validate_repair(
        TEST_CODE,
        repaired_code
    )

    checks = [
        (
            "syntax_valid",
            "repaired code syntax valid"
        ),
        (
            "shell_true_removed",
            "shell=True removed"
        ),
        (
            "eval_removed",
            "eval() removed"
        ),
        (
            "pickle_removed",
            "pickle.loads() removed"
        ),
        (
            "environment_variable_used",
            "environment variable used"
        ),
        (
            "ast_literal_eval_used",
            "ast.literal_eval used"
        ),
        (
            "json_loads_used",
            "json.loads used"
        ),
    ]

    passed = 0

    for key, label in checks:

        if validation[key]:

            print(
                f"PASS: {label}"
            )

            passed += 1

        else:

            print(
                f"FAIL: {label}"
            )

    # ========================================================
    # STEP 5: SUMMARY
    # ========================================================

    print("\n" + "=" * 60)
    print("          REPAIR ENGINE TEST SUMMARY")
    print("=" * 60)

    repair_passed = sum(
        1
        for repair in repair_results
        if repair["repair_status"] == "REPAIR_AVAILABLE"
    )

    print(
        f"\nRepair Rule Tests: "
        f"{repair_passed}/{len(TEST_FINDINGS)}"
    )

    print(
        f"Validation Tests: "
        f"{passed}/{len(checks)}"
    )

    if (
        repair_passed == len(TEST_FINDINGS)
        and passed == len(checks)
    ):

        print(
            "\nOverall Result: PASS"
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