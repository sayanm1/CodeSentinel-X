import textwrap

from security.unified_scanner import scan_ast


def get_cwe_862_findings(code):
    findings = scan_ast(
        textwrap.dedent(code),
        filename="test_cwe862.py",
    )

    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-862"
    ]


def test_vulnerable_post_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["POST"])
    def update_user(user_id):
        user = db.get(user_id)
        user.name = "updated"
        db.save(user)
    """

    findings = get_cwe_862_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-862"
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_delete_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["DELETE"])
    def delete_user(user_id):
        db.delete(user_id)
    """

    findings = get_cwe_862_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-862"


def test_protected_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["POST"])
    @login_required
    def update_user(user_id):
        user = db.get(user_id)
        user.name = "updated"
        db.save(user)
    """

    findings = get_cwe_862_findings(code)

    assert len(findings) == 0


def test_get_route_not_flagged():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["GET"])
    def get_user(user_id):
        return db.get(user_id)
    """

    findings = get_cwe_862_findings(code)

    assert len(findings) == 0


def test_normal_python_function_not_flagged():
    code = """
    def update_user(user_id):
        user = get_user(user_id)
        user.name = "updated"
        return user
    """

    findings = get_cwe_862_findings(code)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_post_route,
        test_vulnerable_delete_route,
        test_protected_route,
        test_get_route_not_flagged,
        test_normal_python_function_not_flagged,
    ]

    passed = 0

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
        passed += 1

    print(f"\nCWE-862 tests: {passed}/{len(tests)} passed")
