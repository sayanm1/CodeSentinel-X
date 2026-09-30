import textwrap

from security.unified_scanner import scan_ast


def get_cwe_639_findings(code):
    findings = scan_ast(
        textwrap.dedent(code),
        filename="test_cwe639.py",
    )

    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-639"
    ]


def test_vulnerable_user_id_update_route():
    code = """
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/users/update", methods=["POST"])
    def update_user():
        user_id = request.form["user_id"]
        user = User.get(user_id)
        user.email = request.form["email"]
        user.save()
        return "updated"
    """

    findings = get_cwe_639_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-639"
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_account_id_delete_route():
    code = """
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/account/delete", methods=["DELETE"])
    def delete_account():
        account_id = request.args.get("account_id")
        account = Account.find_by_id(account_id)
        account.delete()
        return "deleted"
    """

    findings = get_cwe_639_findings(code)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-639"
    assert findings[0]["severity"] == "HIGH"


def test_protected_owner_check_not_flagged():
    code = """
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/users/update", methods=["POST"])
    def update_user():
        user_id = request.form["user_id"]
        user = User.get(user_id)

        if user.owner_id != current_user.id:
            return "forbidden", 403

        user.email = request.form["email"]
        user.save()
        return "updated"
    """

    findings = get_cwe_639_findings(code)

    assert len(findings) == 0


def test_get_route_not_flagged():
    code = """
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/users/view", methods=["GET"])
    def view_user():
        user_id = request.args.get("user_id")
        user = User.get(user_id)
        return user.name
    """

    findings = get_cwe_639_findings(code)

    assert len(findings) == 0


def test_normal_function_not_flagged():
    code = """
    def update_user_profile(name):
        profile = {
            "name": name
        }
        return profile
    """

    findings = get_cwe_639_findings(code)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_user_id_update_route,
        test_vulnerable_account_id_delete_route,
        test_protected_owner_check_not_flagged,
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
    print(f"CWE-639 tests: {passed}/{len(tests)} passed")

    if passed != len(tests):
        raise SystemExit(1)

    print("Overall Result: PASS")
