from security.unified_scanner import scan_ast


def get_cwe_306_findings(code):
    findings = scan_ast(
        code,
        filename="test_cwe306.py",
    )

    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-306"
    ]


def test_vulnerable_admin_route():
    code = """
from flask import Flask, request

app = Flask(__name__)

@app.route("/admin/delete-user", methods=["POST"])
def delete_user():
    user_id = request.form["user_id"]
    delete_user_from_db(user_id)
    return "deleted"
"""

    findings = get_cwe_306_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-306"
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_password_reset_route():
    code = """
from flask import Flask, request

app = Flask(__name__)

@app.route("/reset-password", methods=["POST"])
def reset_password():
    password = request.form["password"]
    update_password(password)
    return "updated"
"""

    findings = get_cwe_306_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-306"
    assert findings[0]["severity"] == "HIGH"


def test_authenticated_route_not_flagged():
    code = """
from flask import Flask, request

app = Flask(__name__)

@app.route("/admin/delete-user", methods=["POST"])
@login_required
def delete_user():
    user_id = request.form["user_id"]
    delete_user_from_db(user_id)
    return "deleted"
"""

    findings = get_cwe_306_findings(code)

    assert len(findings) == 0


def test_get_route_not_flagged():
    code = """
from flask import Flask

app = Flask(__name__)

@app.route("/admin/settings", methods=["GET"])
def view_settings():
    return "settings"
"""

    findings = get_cwe_306_findings(code)

    assert len(findings) == 0


def test_normal_function_not_flagged():
    code = """
def update_profile(name):
    profile = {
        "name": name
    }
    return profile
"""

    findings = get_cwe_306_findings(code)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_admin_route,
        test_vulnerable_password_reset_route,
        test_authenticated_route_not_flagged,
        test_get_route_not_flagged,
        test_normal_function_not_flagged,
    ]

    passed = 0

    for test in tests:
        try:
            test()
            passed += 1
            print(f"PASS: {test.__name__}")
        except Exception as exc:
            print(f"FAIL: {test.__name__}: {exc}")

    print()
    print(f"CWE-306 tests: {passed}/{len(tests)} passed")

    if passed != len(tests):
        raise SystemExit(1)

    print("Overall Result: PASS")
