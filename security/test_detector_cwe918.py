import ast

from security.unified_scanner import scan_ast


def get_cwe918_findings(source):
    tree = ast.parse(source)
    findings = scan_ast(tree, "cwe918_test.py")
    return [
        finding
        for finding in findings
        if finding.get("cwe") == "CWE-918"
    ]


def test_vulnerable_request_args_url():
    source = """
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text
"""

    findings = get_cwe918_findings(source)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_vulnerable_post_with_user_controlled_target():
    source = """
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/proxy", methods=["POST"])
def proxy():
    target = request.form.get("target")
    response = requests.request("GET", target)
    return response.text
"""

    findings = get_cwe918_findings(source)

    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-918"


def test_protected_url_validation_not_flagged():
    source = """
from flask import Flask, request
import requests

app = Flask(__name__)

def validate_url(url):
    return url.startswith("https://trusted.example.com")

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not validate_url(url):
        return "blocked", 400
    response = requests.get(url)
    return response.text
"""

    findings = get_cwe918_findings(source)

    assert len(findings) == 0


def test_hardcoded_url_not_flagged():
    source = """
from flask import Flask
import requests

app = Flask(__name__)

@app.route("/health")
def health():
    response = requests.get("https://example.com")
    return response.text
"""

    findings = get_cwe918_findings(source)

    assert len(findings) == 0


def test_normal_function_not_flagged():
    source = """
import requests

def fetch_data():
    url = "https://example.com"
    return requests.get(url)
"""

    findings = get_cwe918_findings(source)

    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_vulnerable_request_args_url,
        test_vulnerable_post_with_user_controlled_target,
        test_protected_url_validation_not_flagged,
        test_hardcoded_url_not_flagged,
        test_normal_function_not_flagged,
    ]

    passed = 0

    for test in tests:
        test()
        passed += 1
        print(f"PASS: {test.__name__}")

    print(f"\nCWE-918 Detector Tests: {passed}/{len(tests)} passed")
