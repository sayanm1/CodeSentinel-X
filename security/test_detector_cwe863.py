import textwrap

from security.unified_scanner import scan_ast


def get_cwe_863_findings(code):
    findings = scan_ast(
        textwrap.dedent(code),
        filename="test_cwe863.py",
    )

    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-863"
    ]


def test_vulnerable_authenticated_post_route():
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

    findings = get_cwe_863_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-863"
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_authenticated_delete_route():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["DELETE"])
    @jwt_required
    def delete_user(user_id):
        db.delete(user_id)
    """

    findings = get_cwe_863_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-863"


def test_protected_route_with_ownership_check():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["POST"])
    @login_required
    def update_user(user_id):
        user = db.get(user_id)

        if user.owner_id != current_user.id:
            return "Forbidden", 403

        user.name = "updated"
        db.save(user)
    """

    findings = get_cwe_863_findings(code)

    assert len(findings) == 0


def test_get_route_not_flagged():
    code = """
    from flask import Flask

    app = Flask(__name__)

    @app.route("/users/<user_id>", methods=["GET"])
    @login_required
    def get_user(user_id):
        return db.get(user_id)
    """

    findings = get_cwe_863_findings(code)

    assert len(findings) == 0


def test_normal_python_function_not_flagged():
    code = """
    def update_user(user_id):
        user = get_user(user_id)
        user.name = "updated"
        return user
    """

    findings = get_cwe_863_findings(code)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_authenticated_post_route,
        test_vulnerable_authenticated_delete_route,
        test_protected_route_with_ownership_check,
        test_get_route_not_flagged,
        test_normal_python_function_not_flagged,
    ]

    passed = 0

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
        passed += 1

    print(f"\nCWE-863 tests: {passed}/{len(tests)} passed")
