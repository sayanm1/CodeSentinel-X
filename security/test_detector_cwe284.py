import textwrap

from security.unified_scanner import scan_ast


def get_cwe_284_findings(code):
    findings = scan_ast(
        textwrap.dedent(code),
        filename="test_cwe284.py",
    )

    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-284"
    ]


def test_vulnerable_admin_post_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/admin/users", methods=["POST"])
    def create_user():
        db.create_user()
        return "created"
    """

    findings = get_cwe_284_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-284"
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_delete_user_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/admin/delete_user", methods=["DELETE"])
    def delete_user():
        db.delete_user()
        return "deleted"
    """

    findings = get_cwe_284_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-284"


def test_protected_admin_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/admin/users", methods=["POST"])
    @admin_required
    def create_user():
        db.create_user()
        return "created"
    """

    findings = get_cwe_284_findings(code)

    assert len(findings) == 0


def test_get_route_not_flagged():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/admin/users", methods=["GET"])
    def get_users():
        return db.get_users()
    """

    findings = get_cwe_284_findings(code)

    assert len(findings) == 0


def test_normal_python_function_not_flagged():
    code = """
    def create_user():
        return create_account()
    """

    findings = get_cwe_284_findings(code)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_admin_post_route,
        test_vulnerable_delete_user_route,
        test_protected_admin_route,
        test_get_route_not_flagged,
        test_normal_python_function_not_flagged,
    ]

    passed = 0

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
        passed += 1

    print(f"\nCWE-284 tests: {passed}/{len(tests)} passed")
