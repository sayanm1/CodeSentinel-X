# security/test_closed_loop.py

"""
CodeSentinel-X Closed-Loop Security Verification

Pipeline:

    Vulnerable Code
          ↓
    Unified Security Scanner
          ↓
    Automated Repair Engine
          ↓
    Repair Validation
          ↓
    Re-scan Repaired Code
          ↓
    Before / After Comparison
          ↓
    Final Verification

Run from project root:

    python -m security.test_closed_loop
"""

from security.unified_scanner import analyze_security

from security.repair_engine import (
    generate_repaired_code,
    validate_repair,
)


# ============================================================
# ORIGINAL VULNERABLE CODE
# ============================================================

ORIGINAL_CODE = '''import subprocess
import pickle

password = "admin123"

user = input("Enter command: ")

subprocess.call(
    user,
    shell=True
)

eval(user)

pickle.loads(user)
'''


# ============================================================
# PRINT HELPERS
# ============================================================

def print_separator(char="-", length=60):
    print(char * length)


def print_findings(title, findings):

    print()
    print_separator()
    print(title)
    print_separator()

    if not findings:

        print("No vulnerabilities detected.")

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print()
        print(f"Finding #{index}")

        print(
            "Vulnerability :",
            finding.get(
                "vulnerability",
                "Unknown"
            )
        )

        print(
            "CWE           :",
            finding.get(
                "cwe",
                finding.get(
                    "cwe_id",
                    "Unknown"
                )
            )
        )

        print(
            "Line          :",
            finding.get(
                "line",
                0
            )
        )

        print(
            "Severity      :",
            finding.get(
                "severity",
                "UNKNOWN"
            )
        )

        print(
            "Description   :",
            finding.get(
                "description",
                ""
            )
        )


# ============================================================
# CWE HELPER
# ============================================================

def get_cwe(finding):

    return (
        finding.get("cwe")
        or finding.get("cwe_id")
        or "UNKNOWN"
    )


def build_cwe_set(findings):

    return {
        get_cwe(finding)
        for finding in findings
        if get_cwe(finding) != "UNKNOWN"
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("       CodeSentinel-X CLOSED-LOOP VERIFICATION")
    print("=" * 60)

    # ========================================================
    # STEP 1
    # INITIAL SECURITY SCAN
    # ========================================================

    print("\n[1] Running Initial Security Scan...")

    original_findings = analyze_security(
        ORIGINAL_CODE,
        "original_vulnerable.py"
    )

    print(
        f"Initial scanner detected "
        f"{len(original_findings)} "
        f"vulnerability/vulnerabilities."
    )

    print_findings(
        "INITIAL SECURITY FINDINGS",
        original_findings
    )

    # ========================================================
    # STEP 2
    # EXPECTED CWE VALIDATION
    # ========================================================

    print("\n")
    print_separator("=")
    print("INITIAL VULNERABILITY VALIDATION")
    print_separator("=")

    expected_cwes = {
        "CWE-798",
        "CWE-78",
        "CWE-95",
        "CWE-502",
    }

    detected_cwes = build_cwe_set(
        original_findings
    )

    initial_passed = 0

    for cwe in sorted(expected_cwes):

        if cwe in detected_cwes:

            print(
                f"PASS: {cwe} detected"
            )

            initial_passed += 1

        else:

            print(
                f"FAIL: {cwe} not detected"
            )

    print(
        f"\nInitial detection: "
        f"{initial_passed}/{len(expected_cwes)}"
    )

    # ========================================================
    # STEP 3
    # GENERATE REPAIRED CODE
    # ========================================================

    print("\n")
    print_separator("=")
    print("GENERATING AUTOMATED REPAIR")
    print_separator("=")

    repaired_code = generate_repaired_code(
        ORIGINAL_CODE,
        original_findings
    )

    print(
        "\nRepair candidate generated successfully."
    )

    # ========================================================
    # STEP 4
    # DISPLAY REPAIRED CODE
    # ========================================================

    print("\n")
    print_separator("=")
    print("REPAIRED CODE CANDIDATE")
    print_separator("=")

    print(repaired_code)

    # ========================================================
    # STEP 5
    # REPAIR VALIDATION
    # ========================================================

    print("\n")
    print_separator("=")
    print("REPAIR VALIDATION")
    print_separator("=")

    validation = validate_repair(
        ORIGINAL_CODE,
        repaired_code
    )

    validation_fields = [

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

    validation_passed = 0

    for field, description in validation_fields:

        if validation.get(field):

            print(
                f"PASS: {description}"
            )

            validation_passed += 1

        else:

            print(
                f"FAIL: {description}"
            )

    print(
        f"\nRepair validation: "
        f"{validation_passed}/"
        f"{len(validation_fields)}"
    )

    # ========================================================
    # STEP 6
    # RE-SCAN REPAIRED CODE
    # ========================================================

    print("\n")
    print_separator("=")
    print("RE-SCANNING REPAIRED CODE")
    print_separator("=")

    repaired_findings = analyze_security(
        repaired_code,
        "repaired_code.py"
    )

    print(
        f"\nRepaired-code scanner detected "
        f"{len(repaired_findings)} "
        f"remaining finding(s)."
    )

    print_findings(
        "REMAINING SECURITY FINDINGS",
        repaired_findings
    )

    # ========================================================
    # STEP 7
    # BEFORE / AFTER COMPARISON
    # ========================================================

    print("\n")
    print_separator("=")
    print("BEFORE vs AFTER SECURITY COMPARISON")
    print_separator("=")

    remaining_cwes = build_cwe_set(
        repaired_findings
    )

    comparison_passed = 0

    for cwe in sorted(expected_cwes):

        before = cwe in detected_cwes
        after = cwe in remaining_cwes

        print()
        print(cwe)

        print(
            "    Before :",
            "DETECTED"
            if before
            else "NOT DETECTED"
        )

        print(
            "    After  :",
            "DETECTED"
            if after
            else "RESOLVED"
        )

        if before and not after:

            print(
                "    Status : PASS"
            )

            comparison_passed += 1

        elif not before:

            print(
                "    Status : NOT TESTED"
            )

        else:

            print(
                "    Status : FAIL"
            )

    # ========================================================
    # STEP 8
    # SECURITY REDUCTION
    # ========================================================

    original_count = len(
        original_findings
    )

    repaired_count = len(
        repaired_findings
    )

    if original_count > 0:

        reduction = (
            (original_count - repaired_count)
            / original_count
        ) * 100

    else:

        reduction = 0.0

    # ========================================================
    # STEP 9
    # FINAL SUMMARY
    # ========================================================

    print("\n")
    print_separator("=")
    print("CLOSED-LOOP VERIFICATION SUMMARY")
    print_separator("=")

    print(
        f"\nOriginal vulnerabilities : "
        f"{original_count}"
    )

    print(
        f"Remaining vulnerabilities: "
        f"{repaired_count}"
    )

    print(
        f"Security reduction       : "
        f"{reduction:.1f}%"
    )

    print(
        f"Initial CWE detection    : "
        f"{initial_passed}/"
        f"{len(expected_cwes)}"
    )

    print(
        f"Repair validation        : "
        f"{validation_passed}/"
        f"{len(validation_fields)}"
    )

    print(
        f"CWE resolutions          : "
        f"{comparison_passed}/"
        f"{len(expected_cwes)}"
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    print()

    if (
        initial_passed == len(expected_cwes)
        and validation_passed == len(validation_fields)
        and comparison_passed == len(expected_cwes)
        and repaired_count == 0
    ):

        print(
            "OVERALL RESULT: PASS"
        )

        print(
            "CodeSentinel-X successfully "
            "detected, repaired, validated, "
            "and re-scanned all tested "
            "security vulnerabilities."
        )

    else:

        print(
            "OVERALL RESULT: FAIL"
        )

        print(
            "One or more closed-loop "
            "verification stages failed."
        )

    print("\n")
    print_separator("=")
    print(
        "       CLOSED-LOOP VERIFICATION COMPLETED"
    )
    print_separator("=")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()