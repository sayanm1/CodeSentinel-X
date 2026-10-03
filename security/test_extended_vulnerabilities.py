"""
CodeSentinel-X — Extended 16-CWE Detection Test

Run from the project root:

    python -m security.test_extended_vulnerabilities
"""

from security.unified_scanner import analyze_security


TEST_CODE = r"""
import pickle
import subprocess
import requests
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)


# ============================================================
# CWE-798 — Hardcoded Secret
# ============================================================

password = "admin123"


# ============================================================
# CWE-78 — Command Injection
# ============================================================

user_command = request.args.get("command")

subprocess.call(
    user_command,
    shell=True
)


# ============================================================
# CWE-95 — Code Injection
# ============================================================

expression = request.args.get("expression")

eval(expression)


# ============================================================
# CWE-502 — Unsafe Deserialization
# ============================================================

serialized_data = request.args.get("data")

pickle.loads(serialized_data)


# ============================================================
# CWE-862 — Missing Authorization
# ============================================================

@app.route("/admin/update", methods=["POST"])
def admin_update():

    user_id = request.form.get("user_id")

    update_user(user_id)

    return "updated"


# ============================================================
# CWE-863 — Incorrect Authorization
# ============================================================

@app.route("/user/update", methods=["POST"])
def user_update():

    user_id = request.form.get("user_id")

    if current_user.is_authenticated:
        update_user(user_id)

    return "updated"


# ============================================================
# CWE-284 — Improper Access Control
# ============================================================

@app.route("/admin/settings", methods=["POST"])
def admin_settings():

    change_system_settings()

    return "settings changed"


# ============================================================
# CWE-306 — Missing Authentication
# ============================================================

@app.route("/admin/delete", methods=["POST"])
def admin_delete():

    delete_user(
        request.form.get("user_id")
    )

    return "deleted"


# ============================================================
# CWE-639 — Authorization Bypass Through
# User-Controlled Key
# ============================================================

@app.route("/profile", methods=["GET"])
def profile():

    user_id = request.args.get("user_id")

    return get_user_profile(user_id)


# ============================================================
# CWE-918 — Server-Side Request Forgery
# ============================================================

url = request.args.get("url")

requests.get(url)


# ============================================================
# CWE-79 — Cross-Site Scripting
# ============================================================

name = request.args.get("name")

@app.route("/hello")
def hello():

    return "<h1>Hello " + name + "</h1>"


# ============================================================
# CWE-89 — SQL Injection
# ============================================================

username = request.args.get("username")

query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "'"
)

connection.execute(query)


# ============================================================
# CWE-1336 — Server-Side Template Injection
# ============================================================

template = request.args.get("template")

render_template_string(template)


# ============================================================
# CWE-22 — Path Traversal
# ============================================================

filename = request.args.get("filename")

with open(
    "/var/data/" + filename,
    "r"
) as file:

    data = file.read()


# ============================================================
# CWE-434 — Unrestricted File Upload
# ============================================================

@app.route("/upload", methods=["POST"])
def upload():

    uploaded_file = request.files["file"]

    uploaded_file.save(
        "/var/www/uploads/"
        + uploaded_file.filename
    )

    return "uploaded"


# ============================================================
# CWE-352 — Cross-Site Request Forgery
# ============================================================

@app.route("/change-email", methods=["POST"])
def change_email():

    email = request.form.get("email")

    update_email(email)

    return "email changed"
"""


EXPECTED_CWES = {
    "CWE-798",
    "CWE-78",
    "CWE-95",
    "CWE-502",
    "CWE-862",
    "CWE-863",
    "CWE-284",
    "CWE-306",
    "CWE-639",
    "CWE-918",
    "CWE-79",
    "CWE-89",
    "CWE-1336",
    "CWE-22",
    "CWE-434",
    "CWE-352",
}


def main():

    print("=" * 70)
    print("      CodeSentinel-X — 16-CWE Detection Test")
    print("=" * 70)
    print()

    findings = analyze_security(
        TEST_CODE,
        "test_extended_vulnerabilities.py"
    )

    print(
        f"Scanner detected {len(findings)} final findings."
    )

    print("-" * 70)

    for index, finding in enumerate(findings, 1):

        print(f"Finding #{index}")

        print(
            f"Vulnerability : "
            f"{finding.get('vulnerability')}"
        )

        print(
            f"CWE           : "
            f"{finding.get('cwe')}"
        )

        print(
            f"CWE Name      : "
            f"{finding.get('cwe_name')}"
        )

        print(
            f"Line          : "
            f"{finding.get('line')}"
        )

        print(
            f"Severity      : "
            f"{finding.get('severity')}"
        )

        print(
            f"Risk Score    : "
            f"{finding.get('risk_score')}"
        )

        print(
            f"Description   : "
            f"{finding.get('description')}"
        )

        print("-" * 70)

    detected_cwes = {
        finding.get("cwe")
        for finding in findings
        if finding.get("cwe")
    }

    missing_cwes = EXPECTED_CWES - detected_cwes
    extra_cwes = detected_cwes - EXPECTED_CWES

    print()
    print("=" * 70)
    print("                    CWE COVERAGE")
    print("=" * 70)

    print(
        f"Expected CWE classes : "
        f"{len(EXPECTED_CWES)}"
    )

    print(
        f"Detected CWE classes : "
        f"{len(detected_cwes)}"
    )

    print(
        f"Missing CWE classes  : "
        f"{sorted(missing_cwes)}"
    )

    print(
        f"Extra CWE classes    : "
        f"{sorted(extra_cwes)}"
    )

    print()

    print("Detected CWE list:")
    for cwe in sorted(detected_cwes):
        print(f"  ✓ {cwe}")

    print()

    if not missing_cwes:

        print(
            "RESULT: PASS"
        )

        print(
            "All 16 expected CWE classes "
            "were detected successfully."
        )

    else:

        print(
            "RESULT: PARTIAL"
        )

        print(
            "Some expected CWE classes "
            "were not detected."
        )

        print()
        print("CWE classes requiring investigation:")

        for cwe in sorted(missing_cwes):
            print(f"  ✗ {cwe}")


if __name__ == "__main__":
    main()
    