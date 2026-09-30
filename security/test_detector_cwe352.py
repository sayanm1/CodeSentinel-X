from security.unified_scanner import scan_ast


def run_test(name, code, expected_cwe):
    findings = scan_ast(code, filename=f"{name}.py")
    cwes = {finding.get("cwe") for finding in findings}

    passed = expected_cwe in cwes

    print(
        f"{name}: "
        f"{'PASS' if passed else 'FAIL'} "
        f"| Findings: {len(findings)} "
        f"| CWEs: {sorted(cwes, key=str)}"
    )

    return passed


def run_benign_test(name, code):
    findings = scan_ast(code, filename=f"{name}.py")
    passed = not findings

    print(
        f"{name}: "
        f"{'PASS' if passed else 'FAIL'} "
        f"| Findings: {len(findings)}"
    )

    return passed


print("=" * 70)
print("CodeSentinel-X — CWE-352 CSRF Detector Test")
print("=" * 70)


# Test 1: Vulnerable Flask POST route
vulnerable_post = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
def transfer():
    amount = request.form["amount"]
    return "Transferred " + amount
'''

test1 = run_test(
    "Vulnerable POST route",
    vulnerable_post,
    "CWE-352",
)


# Test 2: Vulnerable PUT route
vulnerable_put = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/update", methods=["PUT"])
def update():
    value = request.json["value"]
    return str(value)
'''

test2 = run_test(
    "Vulnerable PUT route",
    vulnerable_put,
    "CWE-352",
)


# Test 3: Protected route with CSRF validation
protected_route = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
def transfer():
    csrf_token = request.form["csrf_token"]

    if not validate_csrf(csrf_token):
        return "Forbidden", 403

    amount = request.form["amount"]
    return "Transferred " + amount
'''

test3_findings = scan_ast(
    protected_route,
    filename="protected_route.py",
)

test3 = "CWE-352" not in {
    finding.get("cwe")
    for finding in test3_findings
}

print(
    f"Protected POST route: "
    f"{'PASS' if test3 else 'FAIL'} "
    f"| Findings: {len(test3_findings)}"
)


# Test 4: Normal GET route
benign_get = '''
from flask import Flask

app = Flask(__name__)

@app.route("/hello", methods=["GET"])
def hello():
    return "Hello"
'''

test4 = run_benign_test(
    "Normal GET route",
    benign_get,
)


# Test 5: Static Python function
benign_python = '''
def calculate_total(a, b):
    return a + b
'''

test5 = run_benign_test(
    "Static Python function",
    benign_python,
)


passed = sum([
    test1,
    test2,
    test3,
    test4,
    test5,
])

print()
print("=" * 70)
print(f"RESULT: {passed}/5 tests passed")
print("=" * 70)

if passed != 5:
    raise SystemExit(1)
