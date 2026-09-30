# security/test_detector_batch1.py

from security.unified_scanner import analyze_security


# ============================================================
# TEST HELPERS
# ============================================================

def get_cwes(findings):
    return {
        finding.get("cwe")
        for finding in findings
        if finding.get("cwe")
    }


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
# TEST 1 — XSS
# ============================================================

xss_code = """
from flask import request

user_input = request.args.get("name")

response.write(
    "<html>" + user_input + "</html>"
)
"""

xss_findings = analyze_security(
    xss_code,
    "xss_test.py"
)

print_findings(
    "TEST 1 — CROSS-SITE SCRIPTING (CWE-79)",
    xss_findings
)

xss_cwes = get_cwes(xss_findings)

if "CWE-79" in xss_cwes:
    print("PASS: CWE-79 detected")
else:
    print("FAIL: CWE-79 was not detected")


# ============================================================
# TEST 2 — SQL INJECTION
# ============================================================

sql_code = """
import sqlite3

user_input = input("Enter username: ")

query = "SELECT * FROM users WHERE name = '" + user_input + "'"

connection = sqlite3.connect("users.db")

connection.execute(query)
"""

sql_findings = analyze_security(
    sql_code,
    "sql_test.py"
)

print_findings(
    "TEST 2 — SQL INJECTION (CWE-89)",
    sql_findings
)

sql_cwes = get_cwes(sql_findings)

if "CWE-89" in sql_cwes:
    print("PASS: CWE-89 detected")
else:
    print("FAIL: CWE-89 was not detected")


# ============================================================
# TEST 3 — SERVER-SIDE TEMPLATE INJECTION
# ============================================================

ssti_code = """
from jinja2 import Template

user_input = input("Enter template content: ")

template = Template(
    "<h1>" + user_input + "</h1>"
)
"""

ssti_findings = analyze_security(
    ssti_code,
    "ssti_test.py"
)

print_findings(
    "TEST 3 — SERVER-SIDE TEMPLATE INJECTION (CWE-1336)",
    ssti_findings
)

ssti_cwes = get_cwes(ssti_findings)

if "CWE-1336" in ssti_cwes:
    print("PASS: CWE-1336 detected")
else:
    print("FAIL: CWE-1336 was not detected")


# ============================================================
# TEST 4 — BENIGN CODE
# ============================================================

benign_code = """
import sqlite3

connection = sqlite3.connect("users.db")

query = "SELECT * FROM users"

connection.execute(query)

name = "Sayan"

print(name)
"""

benign_findings = analyze_security(
    benign_code,
    "benign_test.py"
)

print_findings(
    "TEST 4 — BENIGN CODE",
    benign_findings
)

if len(benign_findings) == 0:
    print("PASS: No false-positive findings")
else:
    print(
        "FAIL: Unexpected finding(s) detected in benign code"
    )


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("BATCH 1 DETECTOR TEST SUMMARY")
print("=" * 70)

tests_passed = 0
total_tests = 4

if "CWE-79" in xss_cwes:
    tests_passed += 1

if "CWE-89" in sql_cwes:
    tests_passed += 1

if "CWE-1336" in ssti_cwes:
    tests_passed += 1

if len(benign_findings) == 0:
    tests_passed += 1

print(
    f"Tests passed: {tests_passed}/{total_tests}"
)

if tests_passed == total_tests:
    print("OVERALL RESULT: PASS")
else:
    print("OVERALL RESULT: FAIL")