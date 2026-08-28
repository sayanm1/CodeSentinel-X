# security/test_bandit_scanner.py

"""
CodeSentinel-X Bandit Scanner Test

Run from the project root:

    python -m security.test_bandit_scanner
"""

from security.bandit_scanner import run_bandit


# ============================================================
# TEST CODE
# ============================================================

TEST_CODE = """
import subprocess

password = "admin123"

user = input("Enter command: ")

subprocess.call(
    user,
    shell=True
)
"""


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("       CodeSentinel-X Bandit Security Scanner")
    print("=" * 60)

    # --------------------------------------------------------
    # Run Bandit
    # --------------------------------------------------------

    print("\n[1] Running Bandit scanner...")

    findings = run_bandit(TEST_CODE)

    if findings is None:
        findings = []

    print(
        f"Bandit detected {len(findings)} finding(s)."
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("             BANDIT SCAN RESULTS")
    print("=" * 60)

    if not findings:

        print("\nNo Bandit findings were detected.")

    else:

        for index, finding in enumerate(findings, 1):

            print("\n" + "-" * 60)

            print(
                f"Finding #{index}"
            )

            print("-" * 60)

            if isinstance(finding, dict):

                print(
                    "Test ID       : "
                    f"{finding.get('test_id', 'N/A')}"
                )

                print(
                    "Vulnerability : "
                    f"{finding.get('vulnerability', 'N/A')}"
                )

                print(
                    "Severity      : "
                    f"{finding.get('severity', 'N/A')}"
                )

                print(
                    "Confidence    : "
                    f"{finding.get('confidence', 'N/A')}"
                )

                print(
                    "Line          : "
                    f"{finding.get('line', 'N/A')}"
                )

                print(
                    "Description   : "
                    f"{finding.get('description', 'N/A')}"
                )

                print(
                    "Source        : "
                    f"{finding.get('source', 'N/A')}"
                )

            else:

                print(
                    f"Finding       : {finding}"
                )

    # ========================================================
    # VALIDATION
    # ========================================================

    print("\n" + "=" * 60)
    print("             BANDIT VALIDATION")
    print("=" * 60)

    finding_text = "\n".join(
        str(finding).lower()
        for finding in findings
    )

    # --------------------------------------------------------
    # Check for subprocess shell=True
    # --------------------------------------------------------

    shell_detected = (
        "shell" in finding_text
        or "b602" in finding_text
        or "subprocess" in finding_text
    )

    if shell_detected:

        print(
            "PASS: subprocess/shell security issue detected."
        )

    else:

        print(
            "WARNING: Expected shell-related issue "
            "was not detected."
        )

    # --------------------------------------------------------
    # Check for hardcoded password
    # --------------------------------------------------------

    password_detected = (
        "password" in finding_text
        or "hardcoded" in finding_text
        or "b105" in finding_text
    )

    if password_detected:

        print(
            "PASS: Hardcoded password issue detected."
        )

    else:

        print(
            "INFO: Bandit did not report a "
            "hardcoded password issue."
        )

    # ========================================================
    # FINAL STATUS
    # ========================================================

    print("\n" + "=" * 60)
    print("       BANDIT SCANNER TEST COMPLETED")
    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()