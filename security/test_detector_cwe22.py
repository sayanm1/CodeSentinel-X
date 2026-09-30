# security/test_detector_cwe22.py

from security.unified_scanner import analyze_security


def print_findings(title, findings):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    print(f"Total findings: {len(findings)}")

    for index, finding in enumerate(findings, start=1):
        print("-" * 70)
        print(f"Finding #{index}")
        print("Vulnerability :", finding.get("vulnerability"))
        print("CWE           :", finding.get("cwe"))
        print("CWE Name      :", finding.get("cwe_name"))
        print("Severity      :", finding.get("severity"))
        print("Line          :", finding.get("line"))
        print("Description   :", finding.get("description"))


# ============================================================
# TEST 1 — PATH TRAVERSAL
# ============================================================

path_traversal_code = """
user_input = input("Enter filename: ")

with open(user_input, "r") as file:
    data = file.read()

print(data)
"""

findings = analyze_security(
    path_traversal_code,
    "path_traversal_test.py"
)

print_findings(
    "TEST 1 — PATH TRAVERSAL (CWE-22)",
    findings
)

cwes = {
    finding.get("cwe")
    for finding in findings
}

if "CWE-22" in cwes:
    print("PASS: CWE-22 detected")
else:
    print("FAIL: CWE-22 was not detected")


# ============================================================
# TEST 2 — BENIGN STATIC FILE ACCESS
# ============================================================

benign_code = """
with open("config.json", "r") as file:
    data = file.read()

print(data)
"""

benign_findings = analyze_security(
    benign_code,
    "benign_path_test.py"
)

print_findings(
    "TEST 2 — BENIGN STATIC FILE ACCESS",
    benign_findings
)

if len(benign_findings) == 0:
    print("PASS: No false-positive findings")
else:
    print("FAIL: Unexpected finding(s) detected")


# ============================================================
# TEST 3 — PATH VARIABLE
# ============================================================

path_variable_code = """
path = input("Enter path: ")

file = open(path, "r")

content = file.read()

print(content)
"""

path_variable_findings = analyze_security(
    path_variable_code,
    "path_variable_test.py"
)

print_findings(
    "TEST 3 — USER-CONTROLLED PATH VARIABLE",
    path_variable_findings
)

path_variable_cwes = {
    finding.get("cwe")
    for finding in path_variable_findings
}

if "CWE-22" in path_variable_cwes:
    print("PASS: CWE-22 detected for path variable")
else:
    print("FAIL: CWE-22 was not detected for path variable")


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("CWE-22 DETECTOR TEST SUMMARY")
print("=" * 70)

tests_passed = 0
total_tests = 3

if "CWE-22" in cwes:
    tests_passed += 1

if len(benign_findings) == 0:
    tests_passed += 1

if "CWE-22" in path_variable_cwes:
    tests_passed += 1

print(
    f"Tests passed: {tests_passed}/{total_tests}"
)

if tests_passed == total_tests:
    print("OVERALL RESULT: PASS")
else:
    print("OVERALL RESULT: FAIL")